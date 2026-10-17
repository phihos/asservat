import React from 'react';
import {createRoot} from 'react-dom/client';
import {Button} from 'react-aria-components';
import {QueryClient, QueryClientProvider} from '@tanstack/react-query';
const client = new QueryClient({defaultOptions: {
  queries: {retry: false, refetchOnWindowFocus: false, refetchOnReconnect: false, gcTime: 0},
  mutations: {retry: false}
}});
function App() {
  const [paused,setPaused] = React.useState(false);
  return <main><h1>Synthetic dependency experiment</h1><p>No capture or evidence service is connected.</p>
    <Button onPress={()=>setPaused(!paused)}>{paused ? 'Resume local preview' : 'Pause local preview'}</Button>
    <p role="status">{paused ? 'Preview paused' : 'Preview active'}</p></main>;
}
createRoot(document.getElementById('root')!).render(<QueryClientProvider client={client}><App/></QueryClientProvider>);
