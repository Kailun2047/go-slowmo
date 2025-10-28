import './App.css'
import CodePanel from './components/code-panel'
import { GlobalStructList } from './components/global-struct-list'
import { Output } from './components/output'
import { ThreadList } from './components/thread-list'

function App() {
  return (
    <>
      <CodePanel />
      <Output />
      <ThreadList />
      <GlobalStructList />
    </>
  )
}

export default App
