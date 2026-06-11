import Link from "next/link";

import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <main className="flex min-h-screen items-center justify-center px-6 py-10">
      <section className="w-full max-w-xl rounded-[2rem] border border-border/70 bg-white/85 p-8 text-center shadow-panel backdrop-blur">
        <p className="text-sm font-medium uppercase tracking-[0.3em] text-primary">404</p>
        <h1 className="mt-4 font-serif text-4xl tracking-tight text-foreground sm:text-5xl">
          This page does not exist.
        </h1>
        <p className="mt-4 text-base leading-7 text-muted-foreground">
          The web app is configured correctly, but this route has not been built yet.
        </p>
        <div className="mt-8 flex justify-center">
          <Button asChild size="lg">
            <Link href="/">Return home</Link>
          </Button>
        </div>
      </section>
    </main>
  );
}