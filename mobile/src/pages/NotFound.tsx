import { useLocation, useNavigate } from 'react-router-dom';
import { useMountEffect } from '@/hooks/useMountEffect';
import { TopBar } from '@/components/TopBar';
import { ButtonPrimary, Spike } from '@/components/design';

const NotFound = () => {
  const location = useLocation();
  const navigate = useNavigate();

  useMountEffect(() => {
    console.error('404 Error: User attempted to access non-existent route:', location.pathname);
  });

  return (
    <div className="bg-canvas h-full min-h-screen flex flex-col">
      <TopBar title="404" back={false} />
      <div className="flex-1 flex flex-col items-center justify-center px-lg text-center">
        <Spike className="w-8 h-8 text-primary" />
        <h2 className="mt-md font-display text-display-lg text-ink">Lost the thread.</h2>
        <p className="mt-sm text-body-md text-body max-w-[28ch]">
          The page you wanted isn&apos;t here. Head back to the overview.
        </p>
        <div className="mt-lg">
          <ButtonPrimary onClick={() => navigate('/dashboard')}>Back to overview</ButtonPrimary>
        </div>
      </div>
    </div>
  );
};

export default NotFound;
