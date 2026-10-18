// SPDX-License-Identifier: Apache-2.0
import * as Popover from "@radix-ui/react-popover";
import {
  flexRender,
  getCoreRowModel,
  getFacetedUniqueValues,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type ColumnFiltersState,
  type FilterFn,
  type Row,
  type SortingState,
} from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ArrowUpDown, Check, Download, ListFilter, Search, X } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";
import { useNavigate } from "react-router";
import { buttonClass } from "../ui/Button";
import { EmptyState } from "../ui/States";

export interface Facet {
  column: string;
  title: string;
  /** label for a raw value (e.g. 1 → "Tier 1"); defaults to the value itself */
  label?: (value: string) => string;
}

/** A column filter that keeps rows whose value is one of the selected values. */
export function inSet<T>(): FilterFn<T> {
  return (row, columnId, selected: string[]) => !selected?.length || selected.includes(String(row.getValue(columnId) ?? ""));
}

function csvCell(v: unknown): string {
  let s = v === null || v === undefined ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`; // spreadsheet formula injection guard
  return /[",\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

/** Sortable, searchable, faceted table. Rows link to `rowHref` (the whole row is clickable, the first link is
 *  the keyboard target). `csv` exports the filtered rows. */
export function DataTable<T>({
  data,
  columns,
  label,
  searchPlaceholder = "Search…",
  facets = [],
  initialSort = [],
  rowHref,
  pageSize = 25,
  csv,
  empty,
  toolbar,
  hidden = [],
}: {
  data: T[];
  columns: ColumnDef<T, unknown>[];
  label: string;
  searchPlaceholder?: string;
  facets?: Facet[];
  initialSort?: SortingState;
  rowHref?: (row: T) => string;
  pageSize?: number;
  csv?: { filename: string; row: (row: T) => Record<string, unknown> };
  empty?: ReactNode;
  toolbar?: ReactNode;
  /** columns used only for filtering or sorting, not shown */
  hidden?: string[];
}) {
  const navigate = useNavigate();
  const [sorting, setSorting] = useState<SortingState>(initialSort);
  const [globalFilter, setGlobalFilter] = useState("");
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
  const table = useReactTable({
    data,
    columns,
    state: { sorting, globalFilter, columnFilters },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalFilter,
    onColumnFiltersChange: setColumnFilters,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getFacetedUniqueValues: getFacetedUniqueValues(),
    getPaginationRowModel: getPaginationRowModel(),
    globalFilterFn: "includesString",
    initialState: { pagination: { pageSize }, columnVisibility: Object.fromEntries(hidden.map((h) => [h, false])) },
  });
  const filtered = table.getFilteredRowModel().rows;
  const exportCsv = () => {
    if (!csv) return;
    const records = filtered.map((r) => csv.row(r.original));
    const head = Object.keys(records[0] ?? {});
    const body = [head.map(csvCell).join(","), ...records.map((rec) => head.map((h) => csvCell(rec[h])).join(","))].join("\n");
    const url = URL.createObjectURL(new Blob([body], { type: "text/csv" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: csv.filename });
    a.click();
    URL.revokeObjectURL(url);
  };
  const activeFilters = columnFilters.length + (globalFilter ? 1 : 0);
  const open = (row: Row<T>) => { if (rowHref) void navigate(rowHref(row.original)); };
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-3">
        <label className="relative flex items-center">
          <span className="sr-only">Search {label}</span>
          <Search className="pointer-events-none absolute left-2.5 size-4 text-muted" aria-hidden="true" />
          <input
            value={globalFilter}
            onChange={(e) => setGlobalFilter(e.target.value)}
            placeholder={searchPlaceholder}
            className="h-8 w-64 rounded-md border border-line bg-page pl-8 pr-2 text-[13px] text-ink placeholder:text-muted focus:border-accent focus:outline-none"
          />
        </label>
        {facets.map((f) => (
          <FacetFilter key={f.column} table={table} facet={f} />
        ))}
        {activeFilters > 0 && (
          <button
            type="button"
            onClick={() => { setGlobalFilter(""); setColumnFilters([]); }}
            className={buttonClass("ghost", "sm")}
          >
            <X className="size-3.5" aria-hidden="true" /> Clear
          </button>
        )}
        <span className="flex-1" />
        <span className="text-xs text-muted" aria-live="polite">
          {filtered.length === data.length ? `${data.length} ${label}` : `${filtered.length} of ${data.length} ${label}`}
        </span>
        {toolbar}
        {csv && (
          <button type="button" onClick={exportCsv} disabled={!filtered.length} className={buttonClass("secondary", "sm")}>
            <Download className="size-3.5" aria-hidden="true" /> CSV
          </button>
        )}
      </div>
      {filtered.length === 0 ? (
        empty ?? <EmptyState icon={Search} title="Nothing matches">Try another search or clear the filters.</EmptyState>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-[13px]">
            <thead>
              {table.getHeaderGroups().map((hg) => (
                <tr key={hg.id}>
                  {hg.headers.map((h) => {
                    const sorted = h.column.getIsSorted();
                    const canSort = h.column.getCanSort();
                    const meta = h.column.columnDef.meta as { align?: "right" } | undefined;
                    return (
                      <th
                        key={h.id}
                        aria-sort={sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : undefined}
                        className={`whitespace-nowrap border-b border-line px-4 py-2.5 text-xs font-medium text-muted ${meta?.align === "right" ? "text-right" : "text-left"}`}
                      >
                        {canSort ? (
                          <button
                            type="button"
                            onClick={h.column.getToggleSortingHandler()}
                            className="inline-flex items-center gap-1 rounded bg-transparent p-0 text-xs font-medium text-muted hover:text-ink"
                          >
                            {flexRender(h.column.columnDef.header, h.getContext())}
                            {sorted === "asc" ? <ArrowUp className="size-3" /> : sorted === "desc" ? <ArrowDown className="size-3" /> : <ArrowUpDown className="size-3 opacity-40" />}
                          </button>
                        ) : (
                          flexRender(h.column.columnDef.header, h.getContext())
                        )}
                      </th>
                    );
                  })}
                </tr>
              ))}
            </thead>
            <tbody>
              {table.getRowModel().rows.map((row) => (
                <tr
                  key={row.id}
                  onClick={rowHref ? (e) => { if (!(e.target as HTMLElement).closest("a,button,input")) open(row); } : undefined}
                  className={`border-b border-line last:border-b-0 ${rowHref ? "cursor-pointer hover:bg-surface-2" : ""}`}
                >
                  {row.getVisibleCells().map((cell) => {
                    const meta = cell.column.columnDef.meta as { align?: "right" } | undefined;
                    return (
                      <td key={cell.id} className={`px-4 py-3 align-middle ${meta?.align === "right" ? "text-right tabular-nums" : ""}`}>
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {table.getPageCount() > 1 && (
        <div className="flex items-center justify-end gap-2 border-t border-line px-4 py-2.5 text-xs text-muted">
          <span>
            Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()}
          </span>
          <button type="button" className={buttonClass("secondary", "sm")} onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()}>
            Previous
          </button>
          <button type="button" className={buttonClass("secondary", "sm")} onClick={() => table.nextPage()} disabled={!table.getCanNextPage()}>
            Next
          </button>
        </div>
      )}
    </div>
  );
}

function FacetFilter<T>({ table, facet }: { table: ReturnType<typeof useReactTable<T>>; facet: Facet }) {
  const column = table.getColumn(facet.column);
  const values = useMemo(
    () => [...(column?.getFacetedUniqueValues().entries() ?? [])].map(([v, n]) => [String(v ?? ""), n] as const).sort(),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [column, table.getCoreRowModel().rows.length],
  );
  if (!column) return null;
  const selected = (column.getFilterValue() as string[] | undefined) ?? [];
  const toggle = (v: string) => {
    const next = selected.includes(v) ? selected.filter((x) => x !== v) : [...selected, v];
    column.setFilterValue(next.length ? next : undefined);
  };
  const name = (v: string) => (facet.label ? facet.label(v) : v || "None");
  return (
    <Popover.Root>
      <Popover.Trigger className={buttonClass(selected.length ? "secondary" : "ghost", "sm", "border-dashed border-line-strong")}>
        <ListFilter className="size-3.5" aria-hidden="true" />
        {facet.title}
        {selected.length > 0 && (
          <span className="rounded bg-accent-soft px-1 text-[11px] text-ink">{selected.length === 1 ? name(selected[0]!) : `${selected.length} selected`}</span>
        )}
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content align="start" sideOffset={6} className="z-50 w-56 rounded-lg border border-line bg-surface p-1 shadow-card">
          <div role="group" aria-label={`Filter by ${facet.title}`}>
            {values.map(([v, n]) => {
              const on = selected.includes(v);
              return (
                <button
                  key={v}
                  type="button"
                  role="menuitemcheckbox"
                  aria-checked={on}
                  onClick={() => toggle(v)}
                  className="flex w-full items-center gap-2 rounded bg-transparent px-2 py-1.5 text-left text-[13px] text-ink-2 hover:bg-surface-3 hover:text-ink"
                >
                  <span className={`flex size-4 items-center justify-center rounded border ${on ? "border-accent bg-accent-solid text-white" : "border-line-strong"}`}>
                    {on && <Check className="size-3" strokeWidth={3} />}
                  </span>
                  <span className="flex-1">{name(v)}</span>
                  <span className="text-xs text-muted">{n}</span>
                </button>
              );
            })}
          </div>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}
