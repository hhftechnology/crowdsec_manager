import { useState } from 'react'
import type { Allowlist as AllowlistType } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'

interface ManageEntriesProps {
  allowlists: AllowlistType[]
  selectedAllowlist: string
  onSelectAllowlist: (name: string) => void
  onAddEntries: (values: string[], expiration?: string, description?: string) => void
  onRemoveEntries: (values: string[]) => void
  isAdding: boolean
  isRemoving: boolean
}

function ManageEntries({
  allowlists,
  selectedAllowlist,
  onSelectAllowlist,
  onAddEntries,
  onRemoveEntries,
  isAdding,
  isRemoving,
}: ManageEntriesProps) {
  const [ipsToAdd, setIpsToAdd] = useState('')
  const [entryDescription, setEntryDescription] = useState('')
  const [expiration, setExpiration] = useState('')
  const [ipsToRemove, setIpsToRemove] = useState('')

  const handleAddEntries = (e: React.FormEvent) => {
    e.preventDefault()
    if (!ipsToAdd.trim()) return
    const values = ipsToAdd.split(/[,\n]/).map(ip => ip.trim()).filter(ip => ip.length > 0)
    onAddEntries(values, expiration || undefined, entryDescription || undefined)
    setIpsToAdd('')
    setEntryDescription('')
    setExpiration('')
  }

  const handleRemoveEntries = (e: React.FormEvent) => {
    e.preventDefault()
    if (!ipsToRemove.trim()) return
    const values = ipsToRemove.split(/[,\n]/).map(ip => ip.trim()).filter(ip => ip.length > 0)
    onRemoveEntries(values)
    setIpsToRemove('')
  }

  const selectClassName = "flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
  const textareaClassName = "flex min-h-[100px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"

  return (
    <Card>
      <CardHeader>
        <CardTitle>Manage Entries</CardTitle>
        <CardDescription>
          Add or remove IP addresses and CIDR ranges from allowlists
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="add">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="add">Add Entries</TabsTrigger>
            <TabsTrigger value="remove">Remove Entries</TabsTrigger>
          </TabsList>

          <TabsContent value="add">
            <form onSubmit={handleAddEntries} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="allowlist-select">Select Allowlist</Label>
                <select
                  id="allowlist-select"
                  className={selectClassName}
                  value={selectedAllowlist}
                  onChange={(e) => onSelectAllowlist(e.target.value)}
                  required
                >
                  <option value="">Choose an allowlist...</option>
                  {allowlists.map((al) => (
                    <option key={al.name} value={al.name}>{al.name}</option>
                  ))}
                </select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="ips-add">IP Addresses or CIDR Ranges</Label>
                <textarea
                  id="ips-add"
                  className={textareaClassName}
                  placeholder={"192.168.1.100\n10.0.0.0/24\n172.16.0.0/16"}
                  value={ipsToAdd}
                  onChange={(e) => setIpsToAdd(e.target.value)}
                  required
                />
                <p className="text-xs text-muted-foreground">
                  Enter one IP or CIDR range per line, or separate with commas
                </p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="expiration">Expiration (optional)</Label>
                  <Input
                    id="expiration"
                    placeholder="7d"
                    value={expiration}
                    onChange={(e) => setExpiration(e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">e.g., 7d, 24h, 30d</p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="entry-desc">Description (optional)</Label>
                  <Input
                    id="entry-desc"
                    placeholder="Internal network"
                    value={entryDescription}
                    onChange={(e) => setEntryDescription(e.target.value)}
                  />
                </div>
              </div>

              <Button type="submit" className="w-full" disabled={isAdding}>
                {isAdding ? 'Adding...' : 'Add Entries'}
              </Button>
            </form>
          </TabsContent>

          <TabsContent value="remove">
            <form onSubmit={handleRemoveEntries} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="allowlist-select-remove">Select Allowlist</Label>
                <select
                  id="allowlist-select-remove"
                  className={selectClassName}
                  value={selectedAllowlist}
                  onChange={(e) => onSelectAllowlist(e.target.value)}
                  required
                >
                  <option value="">Choose an allowlist...</option>
                  {allowlists.map((al) => (
                    <option key={al.name} value={al.name}>{al.name}</option>
                  ))}
                </select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="ips-remove">IP Addresses or CIDR Ranges to Remove</Label>
                <textarea
                  id="ips-remove"
                  className={textareaClassName}
                  placeholder={"192.168.1.100\n10.0.0.0/24"}
                  value={ipsToRemove}
                  onChange={(e) => setIpsToRemove(e.target.value)}
                  required
                />
                <p className="text-xs text-muted-foreground">
                  Enter one IP or CIDR range per line, or separate with commas
                </p>
              </div>

              <Button type="submit" variant="destructive" className="w-full" disabled={isRemoving}>
                {isRemoving ? 'Removing...' : 'Remove Entries'}
              </Button>
            </form>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  )
}

export { ManageEntries }
export type { ManageEntriesProps }
