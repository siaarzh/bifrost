import { databricksKeyConfigSchema, oauthKeyConfigComplete, oauthKeyConfigSchema } from "@/lib/types/schemas";
import { z } from "zod";

type DatabricksKeyConfigForm = z.input<typeof databricksKeyConfigSchema>;
type OAuthKeyConfigForm = z.input<typeof oauthKeyConfigSchema>;
type OAuthKeyConfigPayload = Omit<OAuthKeyConfigForm, "_auth_type">;
type DatabricksKeyConfigPayload = Omit<DatabricksKeyConfigForm, "_auth_type">;

const isSet = (v: { value?: string; ref?: string } | undefined) => Boolean(v?.value || v?.ref);

// stripDatabricksAuthDiscriminator removes the UI-only auth discriminator before the key is
// sent to the API. On the personal access token path the service principal fields are inert,
// so they are dropped: explicitly when the user chose that tab, and otherwise only when the
// pair is incomplete. A complete pair with no discriminator is a valid OAuth M2M key whose
// discriminator was never re-seeded (it is set on mount and after the key resolves), and
// stripping its credentials would silently break the key on save.
export const stripDatabricksAuthDiscriminator = (config: DatabricksKeyConfigForm): DatabricksKeyConfigPayload => {
	const { _auth_type, ...rest } = config;
	const hasPair = isSet(rest.client_id) && isSet(rest.client_secret);
	if (_auth_type === "pat" || (_auth_type !== "oauth_m2m" && !hasPair)) {
		delete rest.client_id;
		delete rest.client_secret;
	}
	return rest;
};

// stripOAuthAuthDiscriminator removes the UI-only auth discriminator before the key is sent
// to the API, and drops the whole block on the API-key path: the form registers it for every
// openai-based key, and an inert block would be refused by the API as half-configured. A whole
// block with no discriminator is a valid OAuth key whose discriminator was never re-seeded, and
// is kept.
export const stripOAuthAuthDiscriminator = (config: OAuthKeyConfigForm | undefined): OAuthKeyConfigPayload | undefined => {
	if (!config) return undefined;
	const { _auth_type, ...rest } = config;
	if (_auth_type === "api_key" || (_auth_type !== "oauth" && !oauthKeyConfigComplete(rest))) {
		return undefined;
	}
	if (rest.grant_type === "client_credentials") {
		delete rest.private_key;
		delete rest.issuer;
		delete rest.subject;
		delete rest.key_id;
		delete rest.signing_algorithm;
		delete rest.assertion_lifetime_seconds;
	} else if (rest.grant_type === "jwt_bearer") {
		delete rest.client_id;
		delete rest.client_secret;
		delete rest.auth_style;
	}
	if (rest.scopes && rest.scopes.length === 0) delete rest.scopes;
	if (rest.extra_params && Object.keys(rest.extra_params).length === 0) delete rest.extra_params;
	for (const field of ["audience", "issuer", "subject", "key_id"] as const) {
		if (rest[field] !== undefined && !String(rest[field]).trim()) delete rest[field];
	}
	return rest;
};

type KeyPayload = Record<string, unknown> & { value?: { value?: string; ref?: string }; oauth_key_config?: OAuthKeyConfigForm };

// applyOAuthAuthMethod shapes the key payload for the chosen authentication method. The update
// API keeps every field the payload omits, so a switch has to say what it clears: the OAuth path
// sends an explicit empty value (otherwise the stored static key survives and, since the server
// prefers a value, keeps being used until it expires), and the API-key path sends an explicit
// null section when editing (a create simply omits it).
export const applyOAuthAuthMethod = (key: KeyPayload, isEditing: boolean): Record<string, unknown> => {
	if (!("oauth_key_config" in key)) {
		return key;
	}
	const { oauth_key_config, ...rest } = key;
	const stripped = stripOAuthAuthDiscriminator(oauth_key_config);
	const out: Record<string, unknown> = { ...rest };
	if (stripped) {
		out.oauth_key_config = stripped;
		if (!isSet(key.value)) {
			out.value = { value: "" };
		}
		return out;
	}
	if (isEditing) {
		out.oauth_key_config = null;
	}
	return out;
};