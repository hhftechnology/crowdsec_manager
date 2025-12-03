import { useState, useRef } from 'react'
import { toast } from 'sonner'
import { Upload, Loader2, FileText, AlertCircle } from 'lucide-react'
import api from '@/lib/api'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'

interface ImportDecisionsDialogProps {
  onSuccess: () => void
}

export function ImportDecisionsDialog({ onSuccess }: ImportDecisionsDialogProps) {
  const [open, setOpen] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0])
    }
  }

  const handleImport = async () => {
    if (!file) return

    setIsLoading(true)
    try {
      await api.crowdsec.importDecisions(file)
      toast.success('Decisions imported successfully')
      setOpen(false)
      setFile(null)
      onSuccess()
    } catch (error: any) {
      toast.error(error.response?.data?.error || 'Failed to import decisions')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline">
          <Upload className="mr-2 h-4 w-4" />
          Import CSV
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[425px]">
        <DialogHeader>
          <DialogTitle>Import Decisions</DialogTitle>
          <DialogDescription>
            Upload a CSV file to import decisions. Max 100 entries.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
            <Alert>
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>CSV Format</AlertTitle>
            <AlertDescription>
                Headers: duration, reason, scope, type, value
            </AlertDescription>
            </Alert>

          <div className="grid w-full max-w-sm items-center gap-1.5">
            <input
              type="file"
              accept=".csv"
              onChange={handleFileChange}
              ref={fileInputRef}
              className="hidden"
            />
            <Button
              variant="secondary"
              className="w-full"
              onClick={() => fileInputRef.current?.click()}
            >
              <FileText className="mr-2 h-4 w-4" />
              {file ? file.name : 'Select CSV File'}
            </Button>
          </div>

          {file && (
            <div className="text-sm text-muted-foreground text-center">
              Ready to import {file.name}
            </div>
          )}
        </div>

        <DialogFooter>
          <Button onClick={handleImport} disabled={!file || isLoading}>
            {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Import
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
