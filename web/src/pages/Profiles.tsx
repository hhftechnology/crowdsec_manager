import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Save, RefreshCw, FileText, RotateCcw } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import api from '@/lib/api'
import { ErrorContexts, getErrorMessage } from '@/lib/api/errors'
import { PageHeader, QueryError } from '@/components/common'

function ProfileEditor({ initialContent }: { initialContent: string }) {
  const queryClient = useQueryClient()
  const [content, setContent] = useState(initialContent)

  const saveMutation = useMutation({
    mutationFn: async ({ restart }: { restart: boolean }) => {
      const response = await api.profiles.update(content, restart)
      return response.data
    },
    onSuccess: (data) => {
      toast.success(data.message || 'Profiles updated successfully')
      queryClient.invalidateQueries({ queryKey: ['profiles'] })
    },
    onError: (error) => {
      toast.error(getErrorMessage(error, 'Failed to update profiles', ErrorContexts.ProfilesSave))
    },
  })

  const loadDefaultMutation = useMutation({
    mutationFn: async () => {
      const response = await api.profiles.get(true)
      return response.data
    },
    onSuccess: (data) => {
      setContent(data.data ?? '')
      if (data.message) toast.success(data.message)
    },
    onError: (error) => {
      toast.error(getErrorMessage(error, 'Failed to load default template', ErrorContexts.ProfilesLoadDefault))
    },
  })

  const saving = saveMutation.isPending && !saveMutation.variables?.restart
  const restarting = saveMutation.isPending && !!saveMutation.variables?.restart

  return (
    <>
      <div className="flex gap-2 justify-end">
        <Button
          variant="outline"
          onClick={() => loadDefaultMutation.mutate()}
          disabled={saving || restarting || loadDefaultMutation.isPending}
        >
          <RotateCcw className="h-4 w-4" />
          Reset to Default
        </Button>
        <Button
          variant="outline"
          onClick={() => saveMutation.mutate({ restart: false })}
          disabled={saving || restarting}
        >
          <Save className="h-4 w-4" />
          {saving ? 'Saving...' : 'Save'}
        </Button>
        <Button
          onClick={() => saveMutation.mutate({ restart: true })}
          disabled={saving || restarting}
        >
          <RefreshCw className={`h-4 w-4 ${restarting ? 'animate-spin' : ''}`} />
          {restarting ? 'Restarting...' : 'Save & Restart'}
        </Button>
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
            className="font-mono min-h-[70vh]"
            spellCheck={false}
          />
        </CardContent>
      </Card>
    </>
  )
}

export default function Profiles() {
  const {
    data: profileData,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ['profiles'],
    queryFn: async () => {
      const response = await api.profiles.get()
      return response.data
    },
  })

  return (
    <div className="space-y-6">
      <PageHeader
        title="Profiles"
        description="Manage your CrowdSec profiles configuration (profiles.yaml)."
      />

      {isError && <QueryError error={error} onRetry={refetch} />}

      {isLoading ? (
        <div className="flex items-center justify-center h-full">Loading...</div>
      ) : (
        <ProfileEditor
          key={profileData?.data?.slice(0, 40) ?? 'empty'}
          initialContent={profileData?.data ?? ''}
        />
      )}
    </div>
  )
}
