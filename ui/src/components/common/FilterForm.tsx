import type { FormEvent, ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Search } from "lucide-react";

interface FilterFormProps {
  children: ReactNode;
  onSubmit: () => void;
  submitLabel?: string;
}

export function FilterForm({
  children,
  onSubmit,
  submitLabel = "Search",
}: FilterFormProps) {
  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    onSubmit();
  }

  return (
    <form onSubmit={handleSubmit} className="card-panel p-4">
      <div className="flex flex-wrap items-end gap-3">
        {children}
        <Button type="submit" size="sm">
          <Search className="mr-1.5 h-3.5 w-3.5" />
          {submitLabel}
        </Button>
      </div>
    </form>
  );
}
