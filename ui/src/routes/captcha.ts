import { createFileRoute } from "@tanstack/react-router";
import { CaptchaPage } from "@/features/captcha/CaptchaPage";

export const Route = createFileRoute("/captcha")({
  component: CaptchaPage,
});
