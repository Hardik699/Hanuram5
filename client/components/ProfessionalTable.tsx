import React from 'react';

interface ProfessionalTableProps {
  headers: string[];
  children: React.ReactNode;
  className?: string;
  title?: string;
}

export function ProfessionalTable({
  headers,
  children,
  className = '',
  title,
}: ProfessionalTableProps) {
  return (
    <div className={`bg-white dark:bg-slate-800 rounded-2xl shadow-elevation-3 border border-slate-200 dark:border-slate-700 overflow-hidden animate-fade-in-up ${className}`}>
      {title && (
        <div className="bg-white dark:bg-slate-800 rounded-t-2xl px-6 py-4 border-b border-slate-200 dark:border-slate-700">
          <h3 className="text-lg font-bold text-slate-900 dark:text-white">
            {title}
          </h3>
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-gradient-to-r from-blue-600 via-blue-700 to-blue-800 dark:from-blue-900 dark:via-blue-900 dark:to-blue-950 border-b-2 border-blue-700 dark:border-blue-800 sticky top-0">
            <tr>
              {headers.map((header, idx) => (
                <th
                  key={idx}
                  className="px-6 py-4 text-left text-xs font-bold text-white uppercase tracking-wider whitespace-nowrap"
                >
                  {header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
            {children}
          </tbody>
        </table>
      </div>
    </div>
  );
}

interface TableRowProps {
  children: React.ReactNode;
  className?: string;
  isEven?: boolean;
}

export function TableRow({ children, className = '', isEven = false }: TableRowProps) {
  return (
    <tr
      className={`transition-all duration-200 group border-l-4 border-l-transparent hover:border-l-blue-500 h-16 ${
        isEven
          ? 'bg-slate-50/50 dark:bg-slate-800/30 hover:bg-blue-50 dark:hover:bg-blue-900/10'
          : 'hover:bg-blue-50 dark:hover:bg-blue-900/10'
      } ${className}`}
    >
      {children}
    </tr>
  );
}

interface TableCellProps {
  children: React.ReactNode;
  className?: string;
  bold?: boolean;
  badge?: 'blue' | 'green' | 'orange' | 'purple' | 'red';
}

export function TableCell({
  children,
  className = '',
  bold = false,
  badge,
}: TableCellProps) {
  if (badge) {
    const badgeClasses = {
      blue: 'bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-800/50',
      green: 'bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-300 border-green-200 dark:border-green-800/50',
      orange: 'bg-orange-100 dark:bg-orange-900/40 text-orange-700 dark:text-orange-300 border-orange-200 dark:border-orange-800/50',
      purple: 'bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300 border-purple-200 dark:border-purple-800/50',
      red: 'bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300 border-red-200 dark:border-red-800/50',
    };

    return (
      <td className={`px-6 py-3 ${className}`}>
        <span
          className={`inline-block px-3 py-1.5 rounded-lg text-xs font-bold border ${badgeClasses[badge]}`}
        >
          {children}
        </span>
      </td>
    );
  }

  return (
    <td className={`px-6 py-3 text-sm ${bold ? 'font-bold' : 'font-medium'} text-slate-900 dark:text-white ${className}`}>
      {children}
    </td>
  );
}

