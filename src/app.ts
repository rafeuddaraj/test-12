import express from "express";
import session from "express-session";
import { randomBytes, randomUUID } from "node:crypto";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  type WebAuthnCredential,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";

const rpName = "Node Auth Lab";
const rpID = "localhost";
const origin = "http://localhost:3000";
const port = 3000;
type RegistrationUserID = NonNullable<
  Parameters<typeof generateRegistrationOptions>[0]["userID"]
>;

type Passkey = {
  id: string;
  publicKey: WebAuthnCredential["publicKey"];
  counter: number;
  deviceType: "singleDevice" | "multiDevice";
  backedUp: boolean;
  transports?: WebAuthnCredential["transports"];
};

type User = {
  id: string;
  email: string;
  webAuthnUserID: RegistrationUserID;
  passkeys: Passkey[];
};

const users = new Map<string, User>();

function findUserByEmail(email: string): User | undefined {
  return [...users.values()].find((user) => user.email === email);
}

function toCredentialDescriptor(passkey: Passkey) {
  if (passkey.transports) {
    return {
      id: passkey.id,
      transports: passkey.transports,
    };
  }

  return { id: passkey.id };
}

function toWebAuthnCredential(passkey: Passkey): WebAuthnCredential {
  if (passkey.transports) {
    return {
      id: passkey.id,
      publicKey: passkey.publicKey,
      counter: passkey.counter,
      transports: passkey.transports,
    };
  }

  return {
    id: passkey.id,
    publicKey: passkey.publicKey,
    counter: passkey.counter,
  };
}

declare module "express-session" {
  interface SessionData {
    currentChallenge?: string;
    pendingUserId?: string;
    userId?: string;
    stepUpUntil?: number;
  }
}

const app = express();

app.use(express.json());
app.use(
  session({
    secret: "replace-this-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 10 * 60 * 1000,
    },
  }),
);

function requireSession(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  next();
}

function requireRecentStepUp(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) {
  if (!req.session.stepUpUntil || req.session.stepUpUntil < Date.now()) {
    return res.status(403).json({ error: "Fresh verification required" });
  }

  next();
}

app.post("/auth/register/options", async (req, res) => {
  const { email } = req.body as { email?: string };

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  let user = findUserByEmail(email);

  if (!user) {
    user = {
      id: randomUUID(),
      email,
      webAuthnUserID: randomBytes(32) as RegistrationUserID,
      passkeys: [],
    };

    users.set(user.id, user);
  }

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: user.email,
    userDisplayName: user.email,
    userID: user.webAuthnUserID,
    attestationType: "none",
    excludeCredentials: user.passkeys.map(toCredentialDescriptor),
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
  });

  req.session.currentChallenge = options.challenge;
  req.session.pendingUserId = user.id;

  return res.json(options);
});

app.post("/auth/register/verify", async (req, res) => {
  const user = users.get(req.session.pendingUserId ?? "");

  if (!user || !req.session.currentChallenge) {
    return res.status(400).json({ verified: false });
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: req.session.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });
  } catch (error) {
    return res.status(400).json({
      verified: false,
      error: error instanceof Error ? error.message : "Registration failed",
    });
  }

  if (!verification.verified || !verification.registrationInfo) {
    return res.status(400).json({ verified: false });
  }

  const { credential, credentialDeviceType, credentialBackedUp } =
    verification.registrationInfo;

  const passkey: Passkey = {
    id: credential.id,
    publicKey: credential.publicKey,
    counter: credential.counter,
    deviceType: credentialDeviceType,
    backedUp: credentialBackedUp,
  };
  if (credential.transports) {
    passkey.transports = credential.transports;
  }
  user.passkeys.push(passkey);

  delete req.session.currentChallenge;
  delete req.session.pendingUserId;

  return res.json({ verified: true });
});

app.post("/auth/login/options", async (req, res) => {
  const { email } = req.body as { email?: string };
  const user = email ? findUserByEmail(email) : undefined;

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: user.passkeys.map(toCredentialDescriptor),
    userVerification: "preferred",
  });

  req.session.currentChallenge = options.challenge;
  req.session.pendingUserId = user.id;

  return res.json(options);
});

app.post("/auth/login/verify", async (req, res) => {
  const user = users.get(req.session.pendingUserId ?? "");

  if (!user || !req.session.currentChallenge) {
    return res.status(400).json({ verified: false });
  }

  const passkey = user.passkeys.find((item) => item.id === req.body.id);
  if (!passkey) {
    return res.status(400).json({ verified: false, error: "Passkey not found" });
  }

  const credential = toWebAuthnCredential(passkey);

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: req.session.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential,
      requireUserVerification: true,
    });
  } catch (error) {
    return res.status(400).json({
      verified: false,
      error: error instanceof Error ? error.message : "Authentication failed",
    });
  }

  if (!verification.verified) {
    return res.status(400).json({ verified: false });
  }

  passkey.counter = verification.authenticationInfo.newCounter;
  req.session.userId = user.id;
  delete req.session.currentChallenge;
  delete req.session.pendingUserId;

  return res.json({ verified: true });
});

app.get("/me", requireSession, (req, res) => {
  const user = users.get(req.session.userId ?? "");

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  return res.json({
    id: user.id,
    email: user.email,
    passkeys: user.passkeys.length,
  });
});

app.post("/auth/step-up/options", requireSession, async (req, res) => {
  const user = users.get(req.session.userId ?? "");
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: user.passkeys.map(toCredentialDescriptor),
    userVerification: "required",
  });

  req.session.currentChallenge = options.challenge;
  return res.json(options);
});

app.post("/auth/step-up/verify", requireSession, async (req, res) => {
  const user = users.get(req.session.userId ?? "");
  const passkey = user?.passkeys.find((item) => item.id === req.body.id);

  if (!user || !passkey || !req.session.currentChallenge) {
    return res.status(400).json({ verified: false });
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: req.session.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: toWebAuthnCredential(passkey),
      requireUserVerification: true,
    });
  } catch (error) {
    return res.status(400).json({
      verified: false,
      error: error instanceof Error ? error.message : "Step-up authentication failed",
    });
  }

  if (!verification.verified) {
    return res.status(400).json({ verified: false });
  }

  passkey.counter = verification.authenticationInfo.newCounter;
  req.session.stepUpUntil = Date.now() + 5 * 60 * 1000;
  delete req.session.currentChallenge;

  return res.json({ verified: true });
});

app.post("/billing/payout", requireSession, requireRecentStepUp, (req, res) => {
  return res.json({ ok: true });
});

app.post("/auth/logout", requireSession, (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({ error: "Failed to logout" });
    }

    return res.json({ ok: true });
  });
});

app.get("/debug/users", (_req, res) => {
  const debugUsers = [...users.values()].map((user) => ({
    id: user.id,
    email: user.email,
    webAuthnUserIDLength: user.webAuthnUserID.length,
    passkeys: user.passkeys.map((passkey) => ({
      id: passkey.id,
      counter: passkey.counter,
      deviceType: passkey.deviceType,
      backedUp: passkey.backedUp,
      transports: passkey.transports ?? [],
    })),
  }));

  return res.json(debugUsers);
});

app.listen(port, () => {
  console.log(`WebAuthn demo listening at ${origin}`);
});
