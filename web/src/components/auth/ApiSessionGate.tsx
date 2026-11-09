import { FormEvent, ReactNode, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '@/lib/api/client'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

type ApiError = {
  response?: { status?: number }
}

function statusOf(error: unknown): number | undefined {
  if (typeof error === 'object' && error !== null && 'response' in error) {
    return (error as ApiError).response?.status
  }
  return undefined
}

export function ApiSessionGate({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const [token, setToken] = useState('')
  const session = useQuery({
    queryKey: ['api-session'],
    retry: false,
    queryFn: async () => {
      await apiClient.get('/session')
      return true
    },
  })
  const login = useMutation({
    mutationFn: async (nextToken: string) => {
      await apiClient.post('/session', { token: nextToken })
    },
    onSuccess: async () => {
      setToken('')
      await queryClient.invalidateQueries({ queryKey: ['api-session'] })
    },
  })

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    login.reset()
    await login.mutateAsync(token).catch(() => undefined)
  }

  if (session.isSuccess) {
    return <>{children}</>
  }

  if (session.isPending || session.isFetching || login.isPending) {
    return (
      <div className="flex min-h-screen items-center justify-center text-sm text-muted-foreground">
        Checking session…
      </div>
    )
  }

  const sessionStatus = statusOf(session.error)
  const loginStatus = statusOf(login.error)
  let error = ''
  if (login.isError) {
    error = loginStatus === 401 ? 'That token was rejected.' : 'The API did not respond. Check that the server is running.'
  } else if (session.isError && sessionStatus !== 401) {
    error = 'The API did not respond. Check that the server is running.'
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Sign in</CardTitle>
          <CardDescription>
            Enter the API token configured on this server. It is kept in an HttpOnly cookie for this site only.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form className="space-y-4" onSubmit={onSubmit}>
            <div className="space-y-2">
              <Label htmlFor="api-token">API token</Label>
              <Input
                id="api-token"
                name="token"
                type="password"
                autoComplete="current-password"
                value={token}
                onChange={(event) => setToken(event.target.value)}
                required
              />
            </div>
            {error ? (
              <p className="text-sm text-destructive" role="alert">
                {error}
              </p>
            ) : null}
            <Button type="submit" disabled={login.isPending || token.trim() === ''}>
              {login.isPending ? 'Checking…' : 'Continue'}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
