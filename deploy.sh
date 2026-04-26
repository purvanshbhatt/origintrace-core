#!/bin/bash
# ==============================================================================
# OriginTrace Deployment Script
# 
# Purpose: Automates the entire isolated GCP deployment, including the 
#          unauthenticated Demo environment and the highly secure, zero-trust 
#          Staging environment with VPC isolation.
#
# Prerequisite: You must be authenticated via `gcloud auth login`.
# ==============================================================================

set -e # Exit immediately if a command exits with a non-zero status

# Configuration defaults
DEFAULT_REGION="us-central1"
PROJECT_ID="origintrace-prod-$(date +%s)" # Generates a unique project ID

echo "============================================================"
echo "🚀 ORIGINTRACE DEPLOYMENT PIPELINE"
echo "============================================================"
echo "This script will create a BRAND NEW, ISOLATED Google Cloud Project."
echo "Project ID will be: $PROJECT_ID"
echo ""

# ------------------------------------------------------------------------------
# 1. Project Initialization
# ------------------------------------------------------------------------------
echo "[*] Step 1: Creating Google Cloud Project..."

# Create project (checks if creation was successful)
gcloud projects create "$PROJECT_ID" --name="OriginTrace Engine"
gcloud config set project "$PROJECT_ID"

# Prompt for Billing Account link
echo ""
echo "[?] We need to link a Billing Account to $PROJECT_ID to use Compute resources."
echo "Available Billing Accounts:"
gcloud beta billing accounts list
echo ""
read -p "Enter the Billing Account ID (e.g., XXXXXX-XXXXXX-XXXXXX): " BILLING_ID

gcloud beta billing projects link "$PROJECT_ID" --billing-account="$BILLING_ID"

echo "[*] Enabling required APIs (this may take a minute)..."
gcloud services enable \
    run.googleapis.com \
    secretmanager.googleapis.com \
    compute.googleapis.com \
    vpcaccess.googleapis.com \
    storage.googleapis.com \
    pubsub.googleapis.com \
    cloudbuild.googleapis.com

# ------------------------------------------------------------------------------
# 2. Secret Management
# ------------------------------------------------------------------------------
echo ""
echo "[*] Step 2: Configuring Secret Manager for GEMINI_API_KEY"

# Ask user securely for the API key
read -sp "Enter your Gemini API Key: " GEMINI_API_KEY
echo ""

# Check if secret already exists (idempotency), otherwise create
if gcloud secrets describe GEMINI_API_KEY >/dev/null 2>&1; then
    echo "  [+] Secret GEMINI_API_KEY already exists. Adding new version."
else
    gcloud secrets create GEMINI_API_KEY --replication-policy="automatic"
fi

# Add the key payload
echo -n "$GEMINI_API_KEY" | gcloud secrets versions add GEMINI_API_KEY --data-file=-

# Retrieve Compute Service Account and grant role
PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format="value(projectNumber)")
COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"

# Sometimes the default SA takes a moment to provision after enabling API
sleep 10 

gcloud secrets add-iam-policy-binding GEMINI_API_KEY \
    --member="serviceAccount:${COMPUTE_SA}" \
    --role="roles/secretmanager.secretAccessor" > /dev/null

echo "  [+] Secrets firmly locked down."

# ------------------------------------------------------------------------------
# 3. The Demo Environment (Serverless)
# ------------------------------------------------------------------------------
echo ""
echo "[*] Step 3: Pushing Demo Environment to Google Cloud Run"

echo "  [+] Submitting remote Docker build..."
gcloud builds submit --tag "gcr.io/$PROJECT_ID/origintrace-demo"

echo "  [+] Deploying container..."
gcloud run deploy origintrace-demo \
    --image="gcr.io/$PROJECT_ID/origintrace-demo" \
    --region="$DEFAULT_REGION" \
    --platform="managed" \
    --allow-unauthenticated \
    --memory="2Gi" \
    --set-secrets="GEMINI_API_KEY=GEMINI_API_KEY:latest"

# ------------------------------------------------------------------------------
# 4. The Staging Environment (Zero-Trust VPC, Cloud NAT, Storage & Queues)
# ------------------------------------------------------------------------------
echo ""
echo "[*] Step 4: Provisioning the Secure Staging Perimeter"

VPC_NAME="origintrace-vpc"
SUBNET_NAME="ot-subnet-us-central1"
CONNECTOR_NAME="ot-vpc-con"
ROUTER_NAME="ot-router"
NAT_NAME="ot-nat"

# Create VPC (Custom mode strictly prevents automatic public subnets)
if gcloud compute networks describe "$VPC_NAME" >/dev/null 2>&1; then
    echo "  [+] VPC $VPC_NAME already exists."
else
    gcloud compute networks create "$VPC_NAME" --subnet-mode=custom
fi

# Create Isolated Subnet with Private Google Access explicitly True
if gcloud compute networks subnets describe "$SUBNET_NAME" --region="$DEFAULT_REGION" >/dev/null 2>&1; then
    echo "  [+] Subnet $SUBNET_NAME already exists."
else
    gcloud compute networks subnets create "$SUBNET_NAME" \
        --network="$VPC_NAME" \
        --range="10.0.0.0/28" \
        --region="$DEFAULT_REGION" \
        --enable-private-ip-google-access
fi

# Create Serverless VPC Access Connector allowing Cloud Run to enter the VPC
if gcloud compute networks vpc-access connectors describe "$CONNECTOR_NAME" --region="$DEFAULT_REGION" >/dev/null 2>&1; then
    echo "  [+] VPC Connector $CONNECTOR_NAME already exists."
else
    gcloud compute networks vpc-access connectors create "$CONNECTOR_NAME" \
        --region="$DEFAULT_REGION" \
        --subnet="$SUBNET_NAME" \
        --subnet-project="$PROJECT_ID"
fi

# Route all outbound traffic into a Cloud NAT (Mandatory if blocking default route)
if gcloud compute routers describe "$ROUTER_NAME" --region="$DEFAULT_REGION" >/dev/null 2>&1; then
    echo "  [+] Router $ROUTER_NAME already exists."
else
    gcloud compute routers create "$ROUTER_NAME" --network="$VPC_NAME" --region="$DEFAULT_REGION"
    gcloud compute routers nats create "$NAT_NAME" --router="$ROUTER_NAME" --region="$DEFAULT_REGION" --auto-allocate-nat-external-ips --nat-all-subnet-ip-ranges
fi

# STRICT EGRESS FIREWALLING
echo "  [+] Enforcing Strict VPC Firewall policies..."

# Rule 1: DENY ALL EGRESS (Stop malware C2 traffic dead)
gcloud compute firewall-rules create ot-deny-all-egress \
    --network="$VPC_NAME" \
    --direction=EGRESS \
    --priority=65534 \
    --action=DENY \
    --destination-ranges="0.0.0.0/0" \
    --rules=all || true

# Rule 2: ALLOW ONLY Private Google APIs block (199.36.153.8/30 is Google Restricted APIs IP space)
gcloud compute firewall-rules create ot-allow-google-apis \
    --network="$VPC_NAME" \
    --direction=EGRESS \
    --priority=1000 \
    --action=ALLOW \
    --destination-ranges="199.36.153.8/30" \
    --rules=tcp:443 || true

# Provision Quarantine Bucket
echo "  [+] Provisioning Event-Driven Buckets..."
BUCKET_NAME="origintrace-quarantine-$PROJECT_ID"
if gcloud storage buckets describe "gs://${BUCKET_NAME}" >/dev/null 2>&1; then
    echo "  [+] Bucket $BUCKET_NAME exists."
else
    # Enforce uniform bucket-level access ensuring permissions are tight
    gcloud storage buckets create "gs://${BUCKET_NAME}" \
        --location="$DEFAULT_REGION" \
        --uniform-bucket-level-access
fi

# Provision Pub/Sub Queue for Async Detonations
echo "  [+] Provisioning Pub/Sub Queue..."
TOPIC_NAME="origintrace-analysis-queue"
if gcloud pubsub topics describe "$TOPIC_NAME" >/dev/null 2>&1; then
    echo "  [+] Topic $TOPIC_NAME exists."
else
    gcloud pubsub topics create "$TOPIC_NAME"
fi

echo "============================================================"
echo "✅ ORIGINTRACE INFRASTRUCTURE DEPLOYMENT COMPLETE"
echo "============================================================"
echo ""
echo "Your DEMO endpoint is live. Check your Cloud Run console for the URL."
echo "Your STAGING perimeter (VPC, NAT, Firewalls, PubSub, GCS) is successfully fenced off and ready."
