import { createFileRoute } from '@tanstack/react-router';
import { Workspace } from '@/components/quantumtrace/workspace';
export const Route = createFileRoute('/inventory')({
 head:()=>({meta:[{title:'QuantumTrace | Crypto Inventory'},{name:'description',content:'Inspect cryptographic algorithms, evidence, and risk across your assets.'},{property:'og:title',content:'QuantumTrace | Crypto Inventory'},{property:'og:description',content:'Inspect cryptographic algorithms, evidence, and risk across your assets.'},{property:'og:type',content:'website'},{name:'twitter:card',content:'summary_large_image'}]}),
 component:()=> <Workspace view="inventory"/>,
});
