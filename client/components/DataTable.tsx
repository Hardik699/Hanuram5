import React, { useState, useMemo } from "react";
import { cn } from "@/lib/utils";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { ChevronLeft, ChevronRight, Search } from "lucide-react";

export interface Column<T> {
  key: keyof T;
  label: string;
  render?: (value: any, row: T) => React.ReactNode;
  sortable?: boolean;
  className?: string;
}

interface DataTableProps<T extends { _id?: string; id?: string }> {
  data: T[];
  columns: Column<T>[];
  title?: string;
  searchable?: boolean;
  searchPlaceholder?: string;
  selectable?: boolean;
  onSelectionChange?: (selected: T[]) => void;
  rowClassName?: (row: T) => string;
  onRowClick?: (row: T) => void;
  paginated?: boolean;
  pageSize?: number;
  className?: string;
}

export function DataTable<T extends { _id?: string; id?: string }>({
  data,
  columns,
  title,
  searchable = true,
  searchPlaceholder = "Search...",
  selectable = false,
  onSelectionChange,
  rowClassName,
  onRowClick,
  paginated = true,
  pageSize = 10,
  className,
}: DataTableProps<T>) {
  const [searchTerm, setSearchTerm] = useState("");
  const [sortKey, setSortKey] = useState<keyof T | null>(null);
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("asc");
  const [currentPage, setCurrentPage] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  // Filter data based on search term
  const filteredData = useMemo(() => {
    if (!searchTerm.trim()) return data;

    const term = searchTerm.toLowerCase();
    return data.filter((row) =>
      columns.some((col) => {
        const value = row[col.key];
        return String(value).toLowerCase().includes(term);
      }),
    );
  }, [data, searchTerm, columns]);

  // Sort data
  const sortedData = useMemo(() => {
    if (!sortKey) return filteredData;

    return [...filteredData].sort((a, b) => {
      const aVal = a[sortKey];
      const bVal = b[sortKey];

      if (aVal === bVal) return 0;
      if (aVal == null) return 1;
      if (bVal == null) return -1;

      const comparison = String(aVal).localeCompare(String(bVal));
      return sortOrder === "asc" ? comparison : -comparison;
    });
  }, [filteredData, sortKey, sortOrder]);

  // Paginate data
  const paginatedData = useMemo(() => {
    if (!paginated) return sortedData;
    const start = currentPage * pageSize;
    return sortedData.slice(start, start + pageSize);
  }, [sortedData, currentPage, pageSize, paginated]);

  const totalPages = Math.ceil(sortedData.length / pageSize);

  const handleSort = (key: keyof T) => {
    if (sortKey === key) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortKey(key);
      setSortOrder("asc");
    }
    setCurrentPage(0);
  };

  const handleSelectAll = () => {
    if (selected.size === paginatedData.length) {
      setSelected(new Set());
      onSelectionChange?.([]);
    } else {
      const newSelected = new Set(
        paginatedData.map((row) => row._id || row.id || ""),
      );
      setSelected(newSelected);
      onSelectionChange?.(
        paginatedData.filter((row) => newSelected.has(row._id || row.id || "")),
      );
    }
  };

  const handleSelectRow = (row: T) => {
    const id = row._id || row.id || "";
    const newSelected = new Set(selected);
    if (newSelected.has(id)) {
      newSelected.delete(id);
    } else {
      newSelected.add(id);
    }
    setSelected(newSelected);
    onSelectionChange?.(
      paginatedData.filter((r) => newSelected.has(r._id || r.id || "")),
    );
  };

  return (
    <div className={cn("w-full space-y-4", className)}>
      {title && (
        <h2 className="text-xl font-bold bg-gradient-to-r from-blue-600 to-blue-700 dark:from-blue-400 dark:to-blue-500 bg-clip-text text-transparent flex items-center gap-2">
          {title}
        </h2>
      )}

      {searchable && (
        <div className="relative animate-material-fade-in">
          <Search className="absolute left-3 top-3 h-4 w-4 text-slate-400 dark:text-slate-500" />
          <Input
            placeholder={searchPlaceholder}
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(0);
            }}
            className="pl-10 prof-form-input"
          />
        </div>
      )}

      <div className="bg-white dark:bg-slate-800 rounded-2xl shadow-elevation-2 border border-slate-200 dark:border-slate-700 overflow-hidden animate-fade-in-up">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="prof-table-head">
              <tr>
                {selectable && (
                  <th className="px-6 py-4 text-left">
                    <input
                      type="checkbox"
                      checked={
                        paginatedData.length > 0 &&
                        selected.size === paginatedData.length
                      }
                      onChange={handleSelectAll}
                      className="rounded border-2 border-white/50 bg-transparent cursor-pointer"
                    />
                  </th>
                )}
                {columns.map((col) => (
                  <th
                    key={String(col.key)}
                    className={cn(
                      "prof-table-head-cell",
                      col.sortable &&
                        "cursor-pointer hover:bg-white/10 transition-colors",
                      col.className,
                    )}
                    onClick={() => col.sortable && handleSort(col.key)}
                  >
                    <div className="flex items-center gap-2">
                      {col.label}
                      {col.sortable && sortKey === col.key && (
                        <span className="text-xs font-bold">
                          {sortOrder === "asc" ? "↑" : "↓"}
                        </span>
                      )}
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
              {paginatedData.length === 0 ? (
                <tr>
                  <td
                    colSpan={columns.length + (selectable ? 1 : 0)}
                    className="px-6 py-12 text-center text-slate-500 dark:text-slate-400 font-medium"
                  >
                    No data found
                  </td>
                </tr>
              ) : (
                paginatedData.map((row, idx) => (
                  <tr
                    key={String(row._id || row.id || "")}
                    className={cn(
                      "prof-table-row prof-table-row-hover",
                      idx % 2 === 0 && "prof-table-row-even",
                      rowClassName?.(row),
                    )}
                  >
                    {selectable && (
                      <td className="px-6 py-4">
                        <input
                          type="checkbox"
                          checked={selected.has(row._id || row.id || "")}
                          onChange={() => handleSelectRow(row)}
                          className="rounded border-2 border-slate-300 dark:border-slate-600 cursor-pointer accent-blue-600"
                          onClick={(e) => e.stopPropagation()}
                        />
                      </td>
                    )}
                    {columns.map((col) => (
                      <td
                        key={String(col.key)}
                        className={cn("prof-table-cell", col.className)}
                        onClick={() => !selectable && onRowClick?.(row)}
                      >
                        {col.render
                          ? col.render(row[col.key], row)
                          : String(row[col.key] || "-")}
                      </td>
                    ))}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {paginated && totalPages > 1 && (
          <div className="px-6 py-4 border-t-2 border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 flex items-center justify-between flex-wrap gap-4">
            <div className="flex items-center gap-3">
              <span className="text-sm font-bold text-slate-700 dark:text-slate-300">
                Items per page:
              </span>
              <select
                value={pageSize}
                onChange={(e) => {
                  // Note: pageSize is passed as prop, so this is for display only
                  setCurrentPage(0);
                }}
                className="prof-form-select px-3 py-1.5 w-20 text-sm"
              >
                <option value={10}>10</option>
                <option value={20}>20</option>
                <option value={30}>30</option>
              </select>
            </div>

            <div className="flex items-center gap-6">
              <span className="text-sm font-semibold text-slate-600 dark:text-slate-400">
                <span className="font-bold text-blue-600 dark:text-blue-400">
                  {currentPage * pageSize + 1} -{" "}
                  {Math.min((currentPage + 1) * pageSize, sortedData.length)}
                </span>{" "}
                of{" "}
                <span className="font-bold text-slate-900 dark:text-slate-200">
                  {sortedData.length}
                </span>
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setCurrentPage(Math.max(0, currentPage - 1))}
                  disabled={currentPage === 0}
                  className="inline-flex items-center justify-center p-2 rounded-xl border-2 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 hover:border-blue-300 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                  title="Previous Page"
                >
                  <ChevronLeft className="w-5 h-5" />
                </button>
                <span className="text-sm font-bold text-slate-700 dark:text-slate-300 min-w-[80px] text-center">
                  Page {currentPage + 1} of {totalPages || 1}
                </span>
                <button
                  onClick={() =>
                    setCurrentPage(Math.min(totalPages - 1, currentPage + 1))
                  }
                  disabled={currentPage >= totalPages - 1}
                  className="inline-flex items-center justify-center p-2 rounded-xl border-2 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 hover:border-blue-300 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                  title="Next Page"
                >
                  <ChevronRight className="w-5 h-5" />
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

