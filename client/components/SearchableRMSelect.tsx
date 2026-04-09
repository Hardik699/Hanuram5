import React, { useEffect, useRef } from "react";
import { Check, ChevronsUpDown } from "lucide-react";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { cn } from "@/lib/utils";

interface RawMaterial {
  _id: string;
  code: string;
  name: string;
  categoryId: string;
  subCategoryId: string;
  unitId?: string;
  unitName?: string;
  lastAddedPrice?: number;
  lastVendorName?: string;
}

interface SearchableRMSelectProps {
  value: string;
  onChange: (value: string) => void;
  options: RawMaterial[];
  placeholder?: string;
  searchValue?: string;
  onSearchChange?: (value: string) => void;
  error?: boolean;
  disabled?: boolean;
}

export function SearchableRMSelect({
  value,
  onChange,
  options,
  placeholder = "Choose Raw Material",
  searchValue = "",
  onSearchChange,
  error = false,
  disabled = false,
}: SearchableRMSelectProps) {
  const [open, setOpen] = React.useState(false);
  const [internalSearch, setInternalSearch] = React.useState(searchValue);
  const inputRef = useRef<HTMLInputElement>(null);

  // Sync external searchValue with internal state
  useEffect(() => {
    setInternalSearch(searchValue);
  }, [searchValue]);

  // Filter options based on search
  const filteredOptions = options.filter(
    (option) =>
      option.name.toLowerCase().includes(internalSearch.toLowerCase()) ||
      option.code.toLowerCase().includes(internalSearch.toLowerCase()),
  );

  const selectedRM = options.find((rm) => rm._id === value);

  const handleSelect = (selectedValue: string) => {
    onChange(selectedValue);
    setOpen(false);
    setInternalSearch("");
    if (onSearchChange) {
      onSearchChange("");
    }
  };

  const handleSearchChange = (text: string) => {
    setInternalSearch(text);
    if (onSearchChange) {
      onSearchChange(text);
    }
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          disabled={disabled}
          className={cn(
            "w-full px-3 py-2 rounded-lg bg-white dark:bg-slate-800 border transition-all text-left flex justify-between items-center",
            error
              ? "border-red-500 dark:border-red-400"
              : "border-slate-200 dark:border-slate-600",
            "text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500 text-sm",
            disabled && "opacity-50 cursor-not-allowed",
          )}
          role="combobox"
          aria-expanded={open}
        >
          <span className="truncate">
            {selectedRM ? (
              <span>
                {selectedRM.name}{" "}
                <span className="text-slate-500">({selectedRM.code})</span>
              </span>
            ) : (
              <span className="text-slate-500 dark:text-slate-400">
                {placeholder}
              </span>
            )}
          </span>
          <ChevronsUpDown className="h-4 w-4 shrink-0 opacity-50" />
        </button>
      </PopoverTrigger>

      <PopoverContent className="w-full p-0 overflow-hidden">
        <Command shouldFilter={false}>
          <CommandInput
            ref={inputRef}
            placeholder="Search by name or code..."
            value={internalSearch}
            onValueChange={handleSearchChange}
            className="border-none focus:ring-0"
          />
          <CommandList>
            {filteredOptions.length === 0 ? (
              <CommandEmpty>
                {options.length === 0
                  ? "No raw materials available"
                  : "No matching raw materials found"}
              </CommandEmpty>
            ) : (
              <CommandGroup>
                {filteredOptions.map((option) => (
                  <CommandItem
                    key={option._id}
                    value={option._id}
                    onSelect={handleSelect}
                    className="flex items-center justify-between cursor-pointer"
                  >
                    <span>
                      {option.name}{" "}
                      <span className="text-xs text-slate-500">
                        ({option.code})
                      </span>
                    </span>
                    {value === option._id && (
                      <Check className="h-4 w-4 text-indigo-600 dark:text-indigo-400" />
                    )}
                  </CommandItem>
                ))}
              </CommandGroup>
            )}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}

