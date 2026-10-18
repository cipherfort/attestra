// SPDX-License-Identifier: Apache-2.0
import { X } from "lucide-react";
import { useState } from "react";
import type { Me } from "../../api";

const shot = new URLSearchParams(window.location.search).has("shot"); // screenshot mode: no banner

function readHidden(): boolean {
  try {
    return window.sessionStorage.getItem("devbanner") === "hidden";
  } catch {
    return false;
  }
}

export function DevBanner({ me }: { me: Me | undefined }) {
  const [hidden, setHidden] = useState(readHidden);
  if (shot || hidden || (me && me.auth_mode !== "dev")) return null;
  const hide = () => {
    try {
      window.sessionStorage.setItem("devbanner", "hidden");
    } catch {
      /* this page only */
    }
    setHidden(true);
  };
  return (
    <div className="print:hidden flex items-center gap-2 border-b border-line bg-banner px-6 py-1.5 text-xs text-ink-2">
      <span className="flex-1">
        Demo data with development sign-in. Switch person from the account menu (top right) to see what each role sees;
        in production people sign in through your identity provider.
      </span>
      <button type="button" onClick={hide} aria-label="Hide this notice" className="rounded bg-transparent p-0.5 text-muted hover:text-ink">
        <X className="size-3.5" />
      </button>
    </div>
  );
}
