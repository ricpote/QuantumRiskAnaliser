import { createFileRoute } from '@tanstack/react-router';
import { Workspace } from '@/components/quantumtrace/workspace';
export const Route = createFileRoute('/reports')({
 head:()=>({meta:[{title:'QuantumTrace | Reports'},{name:'description',content:'Export cryptographic inventory and audit findings from QuantumTrace.'},{property:'og:title',content:'QuantumTrace | Reports'},{property:'og:description',content:'Export cryptographic inventory and audit findings from QuantumTrace.'},{property:'og:type',content:'website'},{name:'twitter:card',content:'summary_large_image'}]}),
 component:()=> <Workspace view="reports"/>,
});
