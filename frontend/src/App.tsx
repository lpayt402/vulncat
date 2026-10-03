import { lazy, Suspense } from 'react';
import { Center, Loader } from '@mantine/core';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { useAuth } from './auth/AuthContext';
import { AppShellLayout } from './layout/AppShellLayout';
import { LoginPage } from './pages/LoginPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { SetupPage } from './pages/SetupPage';

const AuditPage = lazy(() => import('./pages/AuditPage').then((module) => ({ default: module.AuditPage })));
const DashboardPage = lazy(() => import('./pages/DashboardPage').then((module) => ({ default: module.DashboardPage })));
const ExportsPage = lazy(() => import('./pages/ExportsPage').then((module) => ({ default: module.ExportsPage })));
const FindingsPage = lazy(() => import('./pages/FindingsPage').then((module) => ({ default: module.FindingsPage })));
const HostDetailPage = lazy(() => import('./pages/HostDetailPage').then((module) => ({ default: module.HostDetailPage })));
const HostsPage = lazy(() => import('./pages/HostsPage').then((module) => ({ default: module.HostsPage })));
const IdentityReviewPage = lazy(() =>
  import('./pages/IdentityReviewPage').then((module) => ({ default: module.IdentityReviewPage })),
);
const ImportsPage = lazy(() => import('./pages/ImportsPage').then((module) => ({ default: module.ImportsPage })));
const ReportBuilderPage = lazy(() =>
  import('./pages/ReportBuilderPage').then((module) => ({ default: module.ReportBuilderPage })),
);
const SavedViewsPage = lazy(() =>
  import('./pages/SavedViewsPage').then((module) => ({ default: module.SavedViewsPage })),
);
const SettingsPage = lazy(() => import('./pages/SettingsPage').then((module) => ({ default: module.SettingsPage })));
const UsersPage = lazy(() => import('./pages/UsersPage').then((module) => ({ default: module.UsersPage })));
const ServicesPage = lazy(() => import('./pages/ServicesPage').then((module) => ({ default: module.ServicesPage })));

function RouteLoading() {
  return (
    <Center py={100}>
      <Loader aria-label="Loading page" />
    </Center>
  );
}

function ProtectedRoutes() {
  const { user, loading, setupRequired } = useAuth();
  const location = useLocation();

  if (loading || setupRequired === null) {
    return (
      <Center h="100vh">
        <Loader aria-label="Loading Vulncat" />
      </Center>
    );
  }
  if (setupRequired) return <Navigate to="/setup" replace />;
  if (!user) return <Navigate to="/login" state={{ from: location }} replace />;

  return (
    <AppShellLayout>
      <Suspense fallback={<RouteLoading />}>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/hosts" element={<HostsPage />} />
          <Route path="/hosts/:assetId" element={<HostDetailPage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/services" element={<ServicesPage />} />
          <Route path="/imports" element={<ImportsPage />} />
          <Route path="/identity-review" element={<IdentityReviewPage />} />
          <Route path="/saved-views" element={<SavedViewsPage />} />
          <Route path="/reports" element={<ReportBuilderPage />} />
          <Route path="/exports" element={<ExportsPage />} />
          <Route path="/audit" element={<AuditPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/users" element={<UsersPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </Suspense>
    </AppShellLayout>
  );
}

export function App() {
  const { user, setupRequired, loading } = useAuth();

  if (loading || setupRequired === null) {
    return (
      <Center h="100vh">
        <Loader aria-label="Loading Vulncat" />
      </Center>
    );
  }

  return (
    <Routes>
      <Route
        path="/setup"
        element={
          setupRequired ? (
            <SetupPage />
          ) : (
            <Navigate to={user ? '/' : '/login'} replace />
          )
        }
      />
      <Route
        path="/login"
        element={
          setupRequired ? <Navigate to="/setup" replace /> : user ? <Navigate to="/" replace /> : <LoginPage />
        }
      />
      <Route path="*" element={<ProtectedRoutes />} />
    </Routes>
  );
}
