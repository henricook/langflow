import { useQuery } from "@tanstack/react-query";
import { api } from "../../api";

export interface OIDCConfig {
  enabled: boolean;
  provider_name: string | null;
  disable_local_auth: boolean;
}

export const useGetOIDCConfig = () => {
  return useQuery<OIDCConfig>({
    queryKey: ["oidc-config"],
    queryFn: async () => {
      const response = await api.get<OIDCConfig>("/api/v1/auth/oidc/config");
      return response.data;
    },
    // Cache for 5 minutes
    staleTime: 5 * 60 * 1000,
    // Retry once on failure
    retry: 1,
  });
};
