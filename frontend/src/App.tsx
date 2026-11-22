import { lazy, Suspense } from 'react'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { Layout } from './components/layout/Layout'
import { LandingPage } from './pages/LandingPage'
import { DocsPage } from './pages/DocsPage'

// The analysis views pull in the graph libraries (reactflow, force-graph);
// load them on demand so the landing page stays small.
const WorkbenchPage = lazy(() => import('./pages/WorkbenchPage').then(m => ({ default: m.WorkbenchPage })))
const AnalysisDashboard = lazy(() => import('./components/AnalysisDashboard').then(m => ({ default: m.AnalysisDashboard })))

const PageLoading = () => (
  <div className="flex-grow min-h-screen flex items-center justify-center bg-background text-text-muted font-mono text-sm">
    Loading…
  </div>
)

function App() {
  return (
    <Router>
      <Suspense fallback={<PageLoading />}>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<LandingPage />} />
            <Route path="classic" element={<AnalysisDashboard />} />
            <Route path="docs" element={<DocsPage />} />
          </Route>
          {/* The workbench is a full-screen IDE layout with its own top bar. */}
          <Route path="/app" element={<WorkbenchPage />} />
        </Routes>
      </Suspense>
    </Router>
  )
}

export default App
