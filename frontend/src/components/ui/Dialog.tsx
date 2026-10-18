// SPDX-License-Identifier: Apache-2.0
import { X } from "lucide-react";
import { useEffect, useRef, type ReactNode } from "react";

/** Modal dialog or side drawer on the native <dialog> (focus trap, Esc, inert page behind it, no injected styles,
 *  which the CSP would block). */
export function Dialog({
  open,
  onClose,
  title,
  children,
  footer,
  variant = "dialog",
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  footer?: ReactNode;
  variant?: "dialog" | "drawer";
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    else if (!open && d.open) d.close();
  }, [open]);
  const shape = variant === "drawer"
    ? "m-0 ml-auto h-dvh max-h-dvh w-[560px] max-w-[96vw] rounded-none border-0 border-l"
    : "mx-auto mt-[10vh] w-[560px] max-w-[92vw] rounded-xl border";
  return (
    <dialog
      ref={ref}
      onClose={onClose}
      onClick={(e) => { if (e.target === ref.current) onClose(); }}
      aria-label={title}
      className={`${shape} border-line bg-surface p-0 text-ink shadow-card backdrop:bg-black/60`}
    >
      <div className="flex h-full flex-col">
        <header className="flex items-center gap-3 border-b border-line px-5 py-3.5">
          <h2 className="m-0 flex-1 text-sm font-semibold">{title}</h2>
          <button type="button" onClick={onClose} aria-label="Close" className="rounded bg-transparent p-1 text-muted hover:bg-surface-2 hover:text-ink">
            <X className="size-4" />
          </button>
        </header>
        <div className="flex-1 overflow-y-auto p-5">{children}</div>
        {footer && <footer className="flex justify-end gap-2 border-t border-line px-5 py-3">{footer}</footer>}
      </div>
    </dialog>
  );
}
