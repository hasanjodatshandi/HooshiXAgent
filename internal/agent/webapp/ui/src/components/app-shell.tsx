import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  Loader2,
  Lock,
  Menu,
  PlugZap,
  RefreshCw,
  Server,
  Settings,
} from "lucide-react";
import { toast } from "sonner";
import { Brand } from "@/components/brand";
import { LanguageToggle } from "@/components/language-toggle";
import { StatusBadge } from "@/components/status-badge";
import { ThemeToggle } from "@/components/theme-toggle";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { useMessages } from "@/lib/i18n";
import { connectionView } from "@/lib/status";
import { cn } from "@/lib/utils";
import { useAgent, useAgentData } from "@/stores/agent";

const navigation = [
  { to: "/", key: "overview", icon: LayoutDashboard, end: true },
  { to: "/connect", key: "connect", icon: PlugZap, end: false },
  { to: "/services", key: "services", icon: Server, end: false },
  { to: "/device", key: "device", icon: Settings, end: false },
] as const;

type NavigationKey = (typeof navigation)[number]["key"];

function SidebarContent({ onNavigate }: { onNavigate?: () => void }) {
  const messages = useMessages();
  const version = useAgent((state) => state.data?.version);

  return (
    <div className="flex h-full flex-col gap-6">
      <Brand />
      <nav aria-label={messages.nav.group} className="flex flex-1 flex-col gap-1">
        <p className="px-3 pb-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground/80">
          {messages.nav.group}
        </p>
        {navigation.map((item) => {
          const Icon = item.icon;
          const label = messages.nav[item.key as NavigationKey];
          return (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              onClick={onNavigate}
              className={({ isActive }) =>
                cn(
                  "group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-colors",
                  isActive
                    ? "bg-sidebar-accent text-accent-foreground shadow-sm"
                    : "text-muted-foreground hover:bg-accent/60 hover:text-foreground",
                )
              }
            >
              <Icon className="size-[18px]" aria-hidden />
              <span>{label}</span>
            </NavLink>
          );
        })}
      </nav>
      <div className="space-y-3">
        <div className="hairline" />
        <p className="flex items-center gap-2 text-xs text-muted-foreground">
          <Lock className="size-3.5" aria-hidden />
          {messages.brand.localOnly}
        </p>
        <p className="font-mono text-[11px] text-muted-foreground/80">
          {messages.brand.version} {version ?? "—"}
        </p>
      </div>
    </div>
  );
}

export function AppShell() {
  const messages = useMessages();
  const data = useAgentData();
  const refresh = useAgent((state) => state.refresh);
  const refreshing = useAgent((state) => state.refreshing);
  const location = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    setMenuOpen(false);
  }, [location.pathname]);

  const connection = connectionView(
    { paired: data.paired, pending: Boolean(data.pending), tunnel: data.tunnel },
    messages,
  );
  const activeItem = navigation.find((item) =>
    item.end ? location.pathname === item.to : location.pathname.startsWith(item.to),
  );
  const pageTitle = activeItem ? messages.nav[activeItem.key as NavigationKey] : messages.brand.product;

  useEffect(() => {
    document.title = `${pageTitle} · HooshiX`;
  }, [pageTitle]);

  async function onRefresh() {
    const next = await refresh();
    if (!next) toast.error(messages.errors.loadFailed);
  }

  return (
    <div className="min-h-dvh">
      <div
        aria-hidden
        className="page-grid pointer-events-none fixed inset-x-0 top-0 -z-10 h-72 opacity-40"
      />
      <aside className="fixed inset-y-0 start-0 z-40 hidden w-64 flex-col border-e border-sidebar-border bg-sidebar p-5 lg:flex">
        <SidebarContent />
      </aside>

      <div className="lg:ps-64">
        <header className="sticky top-0 z-30 border-b border-border/70 bg-background/80 backdrop-blur">
          <div className="mx-auto flex h-16 max-w-6xl items-center justify-between gap-3 px-4 sm:px-6 lg:px-8">
            <div className="flex min-w-0 items-center gap-2">
              <Sheet open={menuOpen} onOpenChange={setMenuOpen}>
                <SheetTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="lg:hidden"
                    aria-label={messages.common.menu}
                  >
                    <Menu aria-hidden />
                  </Button>
                </SheetTrigger>
                <SheetContent side="start" className="w-[84%] max-w-xs">
                  <SheetTitle className="sr-only">{messages.nav.group}</SheetTitle>
                  <SidebarContent onNavigate={() => setMenuOpen(false)} />
                </SheetContent>
              </Sheet>
              <Brand compact className="lg:hidden" />
              <span className="hidden truncate text-sm font-semibold lg:inline">{pageTitle}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <StatusBadge
                tone={connection.tone}
                pulse={connection.tone === "success"}
                className="hidden md:inline-flex"
              >
                {connection.label}
              </StatusBadge>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => void onRefresh()}
                disabled={refreshing}
                aria-label={messages.common.refresh}
                title={messages.common.refresh}
              >
                {refreshing ? <Loader2 className="animate-spin" aria-hidden /> : <RefreshCw aria-hidden />}
              </Button>
              <ThemeToggle />
              <LanguageToggle />
            </div>
          </div>
        </header>

        <main className="mx-auto max-w-6xl px-4 py-6 sm:px-6 lg:px-8 lg:py-10">
          <div key={location.pathname} className="animate-fade-up">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
