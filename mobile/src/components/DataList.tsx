import { cn } from '@/lib/utils';
import { ScrollArea } from '@/components/ui/scroll-area';

interface DataListProps<T> {
  items: T[];
  renderItem: (item: T, index: number) => React.ReactNode;
  keyExtractor?: (item: T, index: number) => string | number;
  emptyMessage?: string;
  maxHeight?: string;
  className?: string;
}

export function DataList<T>({
  items,
  renderItem,
  keyExtractor,
  emptyMessage = 'No items.',
  maxHeight = 'max-h-[50vh]',
  className,
}: DataListProps<T>) {
  if (items.length === 0) {
    return <p className="text-sm text-muted-foreground py-2">{emptyMessage}</p>;
  }

  return (
    <ScrollArea className={cn(maxHeight, className)}>
      <div className="space-y-2">
        {items.map((item, i) => (
          <div key={keyExtractor ? keyExtractor(item, i) : i}>{renderItem(item, i)}</div>
        ))}
      </div>
    </ScrollArea>
  );
}
