// SPDX-License-Identifier: Apache-2.0
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";

/** The signed-in person, their roles and permissions (cached; the shell and pages share one request). */
export function useMe() {
  return useQuery({ queryKey: ["me"], queryFn: api.me, staleTime: 60_000 });
}
