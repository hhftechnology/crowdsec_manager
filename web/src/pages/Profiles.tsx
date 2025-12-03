import { useState, useEffect } from 'react'
import { toast } from 'sonner'
import { Save, RefreshCw, FileText } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'

export default function Profiles() {
  const [content, setContent] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [restarting, setRestarting] = useState(false)

  useEffect(() => {
    fetchProfiles()
  }, [])

  const fetchProfiles = async () => {
    try {
      const response = await fetch('/api/profiles')
      const data = await response.json()
      if (data.success) {
        setContent(data.data)
      } else {
        toast.error(data.error || 'Failed to fetch profiles')
      }
    } catch (error) {
      toast.error('Failed to fetch profiles')
    } finally {
      setLoading(false)
    }
  }

  const handleSave = async (restart: boolean) => {
    if (restart) {
      setRestarting(true)
    } else {
      setSaving(true)
    }

    try {
      const response = await fetch('/api/profiles', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          content,
          restart,
        }),
      })
      const data = await response.json()

      if (data.success) {
        toast.success(data.message || 'Profiles updated successfully')
      } else {
        toast.error(data.error || 'Failed to update profiles')
      }
    } catch (error) {
      toast.error('Failed to update profiles')
    } finally {
      setSaving(false)
      setRestarting(false)
    }
  }

  if (loading) {
    return <div className="flex items-center justify-center h-full">Loading...</div>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Profiles</h2>
          <p className="text-muted-foreground">
            Manage your CrowdSec profiles configuration (profiles.yaml).
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => handleSave(false)}
            disabled={saving || restarting}
          >
            <Save className="mr-2 h-4 w-4" />
            {saving ? 'Saving...' : 'Save'}
          </Button>
          <Button
            onClick={() => handleSave(true)}
            disabled={saving || restarting}
          >
            <RefreshCw className={`mr-2 h-4 w-4 ${restarting ? 'animate-spin' : ''}`} />
            {restarting ? 'Restarting...' : 'Save & Restart'}
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            profiles.yaml
          </CardTitle>
          <CardDescription>
            Edit the raw configuration file. Be careful, incorrect configuration can break CrowdSec.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Textarea
            value={content}
            onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setContent(e.target.value)}
            className="font-mono min-h-[600px]"
            spellCheck={false}
          />
        </CardContent>
      </Card>
    </div>
  )
}
