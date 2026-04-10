import { Suspense, lazy, useState, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { TooltipProvider } from '@/components/ui/tooltip';
import { Toaster } from '@/components/ui/toaster';
import { ThemeProvider } from '@/contexts/ThemeContext';
import { ApiProvider, useApi } from '@/contexts/ApiContext';
import { BottomNav } from '@/components/BottomNav';
import { AppErrorBoundary } from '@/components/AppErrorBoundary';
import { OfflineConnectionBanner } from '@/components/OfflineConnectionBanner';
import { FullScreenLoader } from '@/components/FullScreenLoader';
import { Onboarding } from '@/components/Onboarding';
import { RouteLoadingScreen } from '@/components/RouteLoadingScreen';
import { DashboardSkeleton } from '@/components/dashboard/DashboardSkeleton';

import LoginPage from '@/pages/LoginPage';
import NotFound from '@/pages/NotFound';

const queryClient = new QueryClient();
const DashboardPage = lazy(() => import('@/pages/DashboardPage'));
const SecurityPage = lazy(() => import('@/pages/SecurityPage'));
const LogsPage = lazy(() => import('@/pages/LogsPage'));
const ManagementPage = lazy(() => import('@/pages/ManagementPage'));
const AllowlistsPage = lazy(() => import('@/pages/AllowlistsPage'));
const ScenariosPage = lazy(() => import('@/pages/ScenariosPage'));
const HubPage = lazy(() => import('@/pages/HubPage'));
const ContainersPage = lazy(() => import('@/pages/ContainersPage'));
const TerminalPage = lazy(() => import('@/pages/TerminalPage'));
const MorePage = lazy(() => import('@/pages/MorePage'));
const AboutPage = lazy(() => import('@/pages/AboutPage'));

function withRouteFallback(node: ReactNode, fallback: ReactNode = <RouteLoadingScreen />) {
  return <Suspense fallback={fallback}>{node}</Suspense>;
}

function AuthenticatedRoutes() {
  return (
    <div className="max-w-lg mx-auto min-h-screen bg-background safe-top">
      <OfflineConnectionBanner />
      <Routes>
        <Route path="/dashboard" element={withRouteFallback(<DashboardPage />, <DashboardSkeleton showHeader />)} />
        <Route path="/security" element={withRouteFallback(<SecurityPage />)} />
        <Route path="/logs" element={withRouteFallback(<LogsPage />)} />

        <Route path="/management" element={withRouteFallback(<ManagementPage />)} />
        <Route path="/management/allowlists" element={withRouteFallback(<AllowlistsPage />)} />
        <Route path="/management/scenarios" element={withRouteFallback(<ScenariosPage />)} />
        <Route path="/management/hub" element={withRouteFallback(<HubPage />)} />
        <Route path="/management/containers" element={withRouteFallback(<ContainersPage />)} />
        <Route path="/management/terminal" element={withRouteFallback(<TerminalPage />)} />

        <Route path="/more" element={withRouteFallback(<MorePage />)} />
        <Route path="/about" element={withRouteFallback(<AboutPage />)} />

        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
      <BottomNav />
    </div>
  );
}

export function AppRoutes() {
  const { isAuthenticated, isLoading } = useApi();
  const [onboarded, setOnboarded] = useState(
    () => localStorage.getItem('csm_onboarding_complete') === 'true',
  );

  if (!onboarded) {
    return <Onboarding onComplete={() => setOnboarded(true)} />;
  }

  if (isLoading) {
    return <FullScreenLoader message="Connecting to API..." />;
  }

  if (!isAuthenticated) {
    return (
      <Routes>
        <Route path="*" element={<LoginPage />} />
      </Routes>
    );
  }

  return <AuthenticatedRoutes />;
}

const App = () => (
  <QueryClientProvider client={queryClient}>
    <ThemeProvider>
      <TooltipProvider>
        <Toaster />
        <ApiProvider>
          <BrowserRouter>
            <AppErrorBoundary>
              <AppRoutes />
            </AppErrorBoundary>
          </BrowserRouter>
        </ApiProvider>
      </TooltipProvider>
    </ThemeProvider>
  </QueryClientProvider>
);

export default App;
