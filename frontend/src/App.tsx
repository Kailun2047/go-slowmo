import './App.css'
import CodePanel from './components/code-panel'
import { GlobalStructList } from './components/global-struct-list'
import { ThreadList } from './components/thread-list'

function App() {
  return (
    <>
      <CodePanel />
      <ThreadList />
      <GlobalStructList />
    </>
  )
}

export default App
