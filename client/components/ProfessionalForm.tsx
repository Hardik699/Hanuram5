import React from 'react';

interface ProfessionalFormProps {
  onSubmit: (e: React.FormEvent) => void;
  children: React.ReactNode;
  className?: string;
}

export function ProfessionalForm({
  onSubmit,
  children,
  className = '',
}: ProfessionalFormProps) {
  return (
    <form
      onSubmit={onSubmit}
      className={`bg-white dark:bg-slate-800 rounded-2xl shadow-elevation-2 p-8 border border-slate-200 dark:border-slate-700 animate-fade-in-up ${className}`}
    >
      {children}
    </form>
  );
}

interface FormGroupProps {
  label: string;
  children: React.ReactNode;
  error?: string;
  className?: string;
  required?: boolean;
}

export function FormGroup({
  label,
  children,
  error,
  className = '',
  required = false,
}: FormGroupProps) {
  return (
    <div className={`mb-6 ${className}`}>
      <label className="block text-sm font-bold text-slate-700 dark:text-slate-300 uppercase tracking-widest mb-2 text-blue-700 dark:text-blue-400">
        {label} {required && <span className="text-red-600">*</span>}
      </label>
      {children}
      {error && (
        <p className="mt-1 text-xs font-semibold text-red-600 dark:text-red-400">
          {error}
        </p>
      )}
    </div>
  );
}

interface FormActionsProps {
  onSubmit: string;
  onCancel?: () => void;
  loading?: boolean;
  submitLabel?: string;
}

export function FormActions({
  onSubmit,
  onCancel,
  loading = false,
  submitLabel,
}: FormActionsProps) {
  const label = submitLabel || onSubmit;

  return (
    <div className="flex gap-4 pt-6 border-t border-slate-200 dark:border-slate-700">
      <button
        type="submit"
        disabled={loading}
        className="flex-1 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 disabled:from-slate-400 disabled:to-slate-400 disabled:cursor-not-allowed text-white font-bold py-3 px-6 rounded-xl transition-all shadow-elevation-3 hover:shadow-elevation-5 transform hover:scale-105 hover:-translate-y-0.5 whitespace-nowrap"
      >
        {loading ? 'Saving...' : label}
      </button>
      {onCancel && (
        <button
          type="button"
          onClick={onCancel}
          className="flex-1 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-300 font-bold py-3 px-6 rounded-xl transition-all shadow-elevation-1 hover:shadow-elevation-3 transform hover:scale-105 hover:-translate-y-0.5"
        >
          Cancel
        </button>
      )}
    </div>
  );
}

