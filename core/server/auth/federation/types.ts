/** One configured upstream identity provider, as stored in trexdb.sso_provider. */
export interface ProviderConfig {
  id: string;
  displayName: string;
  clientId: string;
  clientSecret: string;
  issuer: string;
  discoveryUrl: string;
  scopes: string;
  claimMap: Record<string, string>;
  groupsSource: "claim" | "graph" | "none";
  groupsClaim: string | null;
  linkPolicy: "verified_email";
  autoProvision: boolean;
}

/** What we learned about a person from an upstream id_token, normalised. */
export interface UpstreamIdentity {
  sub: string;
  email: string;
  name?: string;
  emailVerified: boolean;
}
