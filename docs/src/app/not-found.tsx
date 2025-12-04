import Link from 'next/link';

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center min-h-screen py-12 text-center">
      <h1 className="text-9xl font-bold text-primary">404</h1>
      <h2 className="mt-4 text-3xl font-semibold tracking-tight">Page Not Found</h2>
      <p className="mt-4 text-lg text-muted-foreground max-w-[500px]">
        Sorry, we couldn't find the page you're looking for. It might have been moved or deleted.
      </p>
      <div className="mt-8">
        <Link 
          href="/"
          className="inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-10 px-4 py-2"
        >
          Return Home
        </Link>
      </div>
    </div>
  );
}
