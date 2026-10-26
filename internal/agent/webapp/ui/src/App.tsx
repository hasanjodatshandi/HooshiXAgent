import { useEffect } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { Toaster } from "sonner";
import { AppLoading, LoadErrorScreen, UnauthorizedScreen } from "@/components/app-states";
import { AppShell } from "@/components/app-shell";
import { ConnectPage } from "@/pages/connect";
import { DevicePage } from "@/pages/device";
import { OverviewPage } from "@/pages/overview";
import { ServicesPage } from "@/pages/services";
import { useAgent } from "@/stores/agent";
import { useUi } from "@/stores/ui";

function ProtectedLayout() {
  const data = useAgent((state) => state.data);
  const status = useAgent((state) => state.status);
  const fatal = useAgent((state) => state.fatal);
  const refresh = useAgent((state) => state.refresh);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") void refresh();
    }, 15000);
    const onVisibility = () => {
      if (document.visibilityState === "visible") void refresh();
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [refresh]);

  if (!data) {
    if (fatal) return <UnauthorizedScreen />;
    if (status === "error") return <LoadErrorScreen onRetry={() => void refresh()} />;
    return <AppLoading />;
  }
  return <AppShell />;
}

export function App() {
  const theme = useUi((state) => state.theme);
  const language = useUi((state) => state.language);

  return (
    <>
      <Routes>
        <Route element={<ProtectedLayout />}>
          <Route index element={<OverviewPage />} />
          <Route path="connect" element={<ConnectPage />} />
          <Route path="services" element={<ServicesPage />} />
          <Route path="device" element={<DevicePage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
      <Toaster
        theme={theme}
        dir={language === "fa" ? "rtl" : "ltr"}
        position="bottom-center"
        richColors
        closeButton
        toastOptions={{ classNames: { toast: "font-sans" } }}
      />
    </>
  );
}
