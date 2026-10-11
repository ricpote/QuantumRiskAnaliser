import { ArrowRight } from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { TIER_ORDER, tierIcon, tierLabel, tierMeaning, tierSwatch } from "@/lib/labels";

export function HelpDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] max-w-xl overflow-auto">
        <DialogTitle className="font-display text-2xl font-medium">Help & resources</DialogTitle>
        <DialogDescription>QuantumTrace · Post-quantum readiness</DialogDescription>
        <h3 className="text-lg">Where the findings come from</h3>
        <ul className="space-y-1 text-sm text-muted-foreground">
          <li>
            <b className="text-foreground">Network traffic</b>: TLS and SSH handshakes read from
            packet captures or live probes.
          </li>
          <li>
            <b className="text-foreground">Source code</b>: crypto calls, hard-coded keys and weak
            randomness in Python, Java, Go and JavaScript/TypeScript.
          </li>
          <li>
            <b className="text-foreground">Cloud (AWS)</b>: KMS keys, load balancer listeners and
            certificates from AWS exports.
          </li>
          <li>
            Server configs (nginx, Apache, sshd, Terraform), certificates and keys are read too.
          </li>
        </ul>
        <h3 className="mt-2 text-lg">What the risk tiers mean</h3>
        <ul className="space-y-2 text-sm">
          {TIER_ORDER.map((t) => (
            <li key={t} className="flex gap-3">
              <span
                className={`grid h-5 w-5 shrink-0 place-items-center rounded-sm text-xs text-background ${tierSwatch[t]}`}
                aria-hidden
              >
                {tierIcon[t]}
              </span>
              <span>
                <b>{tierLabel[t]}</b>:{" "}
                <span className="text-muted-foreground">{tierMeaning[t]}</span>
              </span>
            </li>
          ))}
        </ul>
        <p className="text-sm text-muted-foreground">
          Q-Day is the year a quantum computer can break today's public-key cryptography. "Harvest
          now, decrypt later" means traffic recorded today can be read after that day. Review
          cryptographic evidence, assess exposure, and validate replacements against your
          environment before migrating.
        </p>
        <a
          className="btn-ghost w-fit"
          href="https://csrc.nist.gov/projects/post-quantum-cryptography"
          target="_blank"
          rel="noreferrer"
        >
          NIST post-quantum standards
          <ArrowRight className="h-4 w-4" />
        </a>
      </DialogContent>
    </Dialog>
  );
}
