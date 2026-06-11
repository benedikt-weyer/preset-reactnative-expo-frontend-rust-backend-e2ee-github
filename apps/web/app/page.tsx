import Link from "next/link";
import { ArrowRight, Blocks, LockKeyhole, Smartphone } from "lucide-react";

import { Button } from "@/components/ui/button";

const pillars = [
  {
    title: "Next.js App Router",
    description: "Server-rendered pages and a clean TypeScript baseline for web-specific product work.",
    icon: Blocks,
  },
  {
    title: "Tailwind + Design Tokens",
    description: "A warm editorial visual language with reusable spacing, color, and typography primitives.",
    icon: Smartphone,
  },
  {
    title: "shadcn/ui Ready",
    description: "Utility helpers, component aliases, and a starter Button are already wired for new UI slices.",
    icon: LockKeyhole,
  },
];

export default function Home() {
  return (
    <main className="relative overflow-hidden">
      <div className="absolute inset-0 -z-10 bg-grid-paper bg-[size:36px_36px] opacity-40" />

      <section className="mx-auto flex min-h-screen max-w-6xl flex-col justify-between px-6 py-8 sm:px-10 lg:px-12">
        <div className="flex items-center justify-between gap-4 rounded-full border border-border/70 bg-white/70 px-4 py-3 shadow-sm backdrop-blur">
          <div>
            <p className="text-xs uppercase tracking-[0.28em] text-muted-foreground">
              Monorepo Web Surface
            </p>
            <p className="mt-1 text-sm text-foreground/80">
              Next.js, Tailwind CSS, and shadcn/ui inside <span className="font-semibold">apps/web</span>
            </p>
          </div>
          <Button asChild={false} variant="secondary" size="sm">
            <span>Ready to extend</span>
          </Button>
        </div>

        <div className="grid items-end gap-10 py-16 lg:grid-cols-[1.2fr_0.8fr] lg:py-20">
          <div className="max-w-3xl">
            <p className="font-serif text-sm uppercase tracking-[0.35em] text-primary/70">
              Web App Scaffold
            </p>
            <h1 className="mt-5 max-w-4xl font-serif text-5xl leading-none tracking-[-0.04em] text-foreground sm:text-6xl lg:text-7xl">
              A web front end that feels designed, not merely generated.
            </h1>
            <p className="mt-6 max-w-2xl text-balance text-lg leading-8 text-foreground/75 sm:text-xl">
              This starter gives the monorepo a dedicated Next.js surface with a strong visual baseline,
              utility-first styling, and shadcn conventions already in place for product work.
            </p>

            <div className="mt-8 flex flex-col gap-3 sm:flex-row">
              <Button asChild size="lg">
                <Link href="https://nextjs.org/docs">
                  Open Next.js docs
                  <ArrowRight />
                </Link>
              </Button>
              <Button asChild size="lg" variant="outline">
                <Link href="https://ui.shadcn.com/docs">
                  Open shadcn/ui docs
                  <ArrowRight />
                </Link>
              </Button>
            </div>
          </div>

          <div className="rounded-[2rem] border border-border/70 bg-white/80 p-6 shadow-panel backdrop-blur">
            <p className="text-xs uppercase tracking-[0.32em] text-muted-foreground">What shipped</p>
            <div className="mt-5 space-y-4">
              {pillars.map(({ title, description, icon: Icon }) => (
                <article
                  key={title}
                  className="rounded-[1.5rem] border border-border/60 bg-background/80 p-4 transition-transform duration-300 hover:-translate-y-1"
                >
                  <div className="flex items-start gap-4">
                    <div className="rounded-2xl bg-primary/10 p-3 text-primary">
                      <Icon className="size-5" />
                    </div>
                    <div>
                      <h2 className="text-lg font-semibold">{title}</h2>
                      <p className="mt-2 text-sm leading-6 text-foreground/70">{description}</p>
                    </div>
                  </div>
                </article>
              ))}
            </div>
          </div>
        </div>

        <div className="grid gap-4 border-t border-border/60 py-6 text-sm text-foreground/70 sm:grid-cols-3">
          <div>
            <p className="font-semibold text-foreground">Run locally</p>
            <p className="mt-1">Use <span className="font-medium">pnpm dev:web</span> to start the app.</p>
          </div>
          <div>
            <p className="font-semibold text-foreground">Build with Turbo</p>
            <p className="mt-1">The repo build pipeline now tracks Next.js output under <span className="font-medium">.next</span>.</p>
          </div>
          <div>
            <p className="font-semibold text-foreground">Extend with shadcn</p>
            <p className="mt-1">Add more components from the configured <span className="font-medium">components.json</span> baseline.</p>
          </div>
        </div>
      </section>
    </main>
  );
}