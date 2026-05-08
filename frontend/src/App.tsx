import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { Layout } from './components/layout/Layout'
import { LandingPage } from './pages/LandingPage'
import { DocsPage } from './pages/DocsPage'
import { AnalysisDashboard } from './components/AnalysisDashboard'

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<LandingPage />} />
          <Route path="app" element={<AnalysisDashboard />} />
          <Route path="docs" element={<DocsPage />} />
        </Route>
      </Routes>
    </Router>
  )
}

export default App
