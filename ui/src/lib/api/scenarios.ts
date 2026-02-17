import { useQuery } from "@tanstack/react-query";
import { apiGet } from "./client";
import type { Scenario } from "@/types/models";

export function useScenariosQuery() {
  return useQuery({
    queryKey: ["scenarios"],
    queryFn: () => apiGet<Scenario[]>("/scenarios"),
  });
}
