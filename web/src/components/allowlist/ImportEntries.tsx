import { useRef, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Upload } from 'lucide-react'
import api, { AxiosErrorResponse } from '@/lib/api'
import type { Allowlist as AllowlistType } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'

interface ImportEntriesProps {
  allowlists: AllowlistType[]
  selectedAllowlist: string
  onSelectAllowlist: (name: string) => void
}

const selectClassName =
  'flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50'

export function ImportEntries({ allowlists, selectedAllowlist, onSelectAllowlist }: ImportEntriesProps) {
  const queryClient = useQueryClient()
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [expiration, setExpiration] = useState('')
  const [description, setDescription] = useState('')
  const [skipInvalid, setSkipInvalid] = useState(true)
  const [skipPrivate, setSkipPrivate] = useState(false)
  const [skipDuplicates, setSkipDuplicates] = useState(true)

  const importMutation = useMutation({
    mutationFn: (formData: FormData) => api.allowlist.importEntries(formData),
    onSuccess: (response) => {
      const result = response.data.data
      if (result) {
        const { imported, total_input, skipped_invalid, skipped_private, skipped_duplicates } = result
        const skipped = skipped_invalid + skipped_private + skipped_duplicates
        toast.success(
          `Imported ${imported} of ${total_input} entries` +
          (skipped > 0 ? ` (${skipped} skipped: ${skipped_invalid} invalid, ${skipped_private} private, ${skipped_duplicates} duplicate)` : '')
        )
      } else {
        toast.success('Import completed')
      }
      setSelectedFile(null)
      if (fileInputRef.current) fileInputRef.current.value = ''
      queryClient.invalidateQueries({ queryKey: ['allowlist-inspect'] })
    },
    onError: (error: AxiosErrorResponse) => {
      toast.error(error.response?.data?.error || 'Import failed')
    },
  })

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSelectedFile(e.target.files?.[0] ?? null)
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedAllowlist) {
      toast.error('Please select an allowlist')
      return
    }
    if (!selectedFile) {
      toast.error('Please select a file to import')
      return
    }

    const formData = new FormData()
    formData.append('file', selectedFile)
    formData.append('allowlist_name', selectedAllowlist)
    if (expiration) formData.append('expiration', expiration)
    if (description) formData.append('description', description)
    formData.append('skip_invalid', String(skipInvalid))
    formData.append('skip_private', String(skipPrivate))
    formData.append('skip_duplicates', String(skipDuplicates))

    importMutation.mutate(formData)
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Import Entries</CardTitle>
        <CardDescription>
          Upload a plain-text file (one IP/CIDR per line) to bulk-import entries into an allowlist.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="import-allowlist">Target Allowlist</Label>
            <select
              id="import-allowlist"
              className={selectClassName}
              value={selectedAllowlist}
              onChange={(e) => onSelectAllowlist(e.target.value)}
            >
              <option value="">Select an allowlist...</option>
              {allowlists.map((al) => (
                <option key={al.name} value={al.name}>{al.name}</option>
              ))}
            </select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="import-file">File</Label>
            <input
              id="import-file"
              ref={fileInputRef}
              type="file"
              accept=".txt,.csv,.text"
              onChange={handleFileChange}
              className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
            />
            <p className="text-xs text-muted-foreground">
              Plain text file with one IP address or CIDR range per line. Comma-separated values on a single line are also supported. Lines starting with # are ignored.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="import-expiration">Expiration (optional)</Label>
              <Input
                id="import-expiration"
                placeholder="e.g. 7d, 24h, 30d"
                value={expiration}
                onChange={(e) => setExpiration(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="import-description">Description (optional)</Label>
              <Input
                id="import-description"
                placeholder="e.g. Imported from blocklist"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
          </div>

          <div className="rounded-md border p-3 space-y-3">
            <p className="text-sm font-medium">Filters</p>
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <Checkbox
                  id="skip-invalid"
                  checked={skipInvalid}
                  onCheckedChange={(checked) => setSkipInvalid(checked === true)}
                />
                <Label htmlFor="skip-invalid" className="cursor-pointer font-normal">
                  Skip invalid entries
                  <span className="block text-xs text-muted-foreground">
                    Drops tokens that are not valid IP addresses or CIDR ranges
                  </span>
                </Label>
              </div>
              <div className="flex items-center gap-2">
                <Checkbox
                  id="skip-private"
                  checked={skipPrivate}
                  onCheckedChange={(checked) => setSkipPrivate(checked === true)}
                />
                <Label htmlFor="skip-private" className="cursor-pointer font-normal">
                  Skip private/loopback addresses
                  <span className="block text-xs text-muted-foreground">
                    Drops RFC 1918 ranges (10.x, 172.16.x, 192.168.x) and loopback (127.x)
                  </span>
                </Label>
              </div>
              <div className="flex items-center gap-2">
                <Checkbox
                  id="skip-duplicates"
                  checked={skipDuplicates}
                  onCheckedChange={(checked) => setSkipDuplicates(checked === true)}
                />
                <Label htmlFor="skip-duplicates" className="cursor-pointer font-normal">
                  Skip duplicates
                  <span className="block text-xs text-muted-foreground">
                    Drops entries already present in the target allowlist
                  </span>
                </Label>
              </div>
            </div>
          </div>

          <Button type="submit" disabled={importMutation.isPending || !selectedFile} className="w-full">
            <Upload className="h-4 w-4" />
            {importMutation.isPending ? 'Importing...' : 'Import Entries'}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}
