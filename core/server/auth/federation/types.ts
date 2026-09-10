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
  /**
   * Optional per-provider restriction on which verified upstream addresses may
   * link or provision at all. `null` (and an empty list, which loadProviders
   * normalises to `null`) means no restriction — today's behaviour.
   * Entries are bare domains, lower-cased on load.
   */
  emailDomainAllowlist: string[] | null;
  /**
   * Whether a first-time upstream identity may be auto-linked to an existing
   * trex user whose role is elevated. Off by default; see link.ts.
   */
  allowElevatedAutoLink: boolean;
}

/** What we learned about a person from an upstream id_token, normalised. */
export interface UpstreamIdentity {
  sub: string;
  email: string;
  name?: string;
  emailVerified: boolean;
}
