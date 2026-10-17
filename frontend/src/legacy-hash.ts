// SPDX-License-Identifier: Apache-2.0
// Links from before real URLs (/#/apps/APP-00001) keep working. Imported before the router so the router reads the
// rewritten address on creation.
if (window.location.hash.startsWith("#/")) {
  window.history.replaceState(null, "", window.location.hash.slice(1));
}
export {};
