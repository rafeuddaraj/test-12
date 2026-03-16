import {
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";

export async function registerPasskey(email: string) {
  const optionsResp = await fetch("/auth/register/options", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ email }),
  });

  const optionsJSON = await optionsResp.json();
  const registrationResponse = await startRegistration({ optionsJSON });

  const verifyResp = await fetch("/auth/register/verify", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(registrationResponse),
  });

  return verifyResp.json();
}

export async function loginWithPasskey(email: string) {
  const optionsResp = await fetch("/auth/login/options", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ email }),
  });

  const optionsJSON = await optionsResp.json();
  const authenticationResponse = await startAuthentication({ optionsJSON });

  const verifyResp = await fetch("/auth/login/verify", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(authenticationResponse),
  });

  return verifyResp.json();
}

export async function stepUpWithPasskey() {
  const optionsResp = await fetch("/auth/step-up/options", {
    method: "POST",
  });

  const optionsJSON = await optionsResp.json();
  const authenticationResponse = await startAuthentication({ optionsJSON });

  const verifyResp = await fetch("/auth/step-up/verify", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(authenticationResponse),
  });

  return verifyResp.json();
}
