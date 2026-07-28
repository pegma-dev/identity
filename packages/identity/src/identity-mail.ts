import {
  type AcknowledgeTerminalMail,
  type AuthenticatedMailCallback,
  type FailureClassifier,
  type MailPageOptions,
  type MailProvider,
  type MailReconciliationPort,
  type MailWorker,
  type SweepTerminalMailOptions,
  type SweepTerminalMailResult,
} from "@pegma/mail";
import type { Clock } from "@pegma/spine";
import type { Store } from "@pegma/storage-core";

import type { EmailCodeService, IdentityMailRenderer } from "./email-codes.js";
import {
  emailOperationsCollection,
  identityMail,
} from "./email-operation-records.js";

export interface IdentityMailWorkerOptions {
  readonly provider: MailProvider;
  readonly reconciliation: MailReconciliationPort;
  readonly renderer: IdentityMailRenderer;
  readonly workerId: string;
  readonly leaseMilliseconds?: number;
  readonly baseRetryMilliseconds?: number;
  readonly acceptedCallbackMilliseconds?: number;
  readonly classifyFailure?: FailureClassifier;
}

export interface IdentityMailService {
  createWorker(options: IdentityMailWorkerOptions): MailWorker;
  applyAuthenticatedCallback(
    callback: AuthenticatedMailCallback,
  ): ReturnType<typeof identityMail.applyAuthenticatedCallback>;
  acknowledgeTerminal(
    acknowledgement: AcknowledgeTerminalMail,
  ): ReturnType<typeof identityMail.acknowledgeTerminal>;
  sweep(options: SweepTerminalMailOptions): Promise<SweepTerminalMailResult>;
}

export function createIdentityMailService(options: {
  readonly store: Store;
  readonly clock: Clock;
  readonly emailCodes: EmailCodeService;
}): IdentityMailService {
  const records = options.store.collection(emailOperationsCollection);
  return Object.freeze({
    createWorker(input: IdentityMailWorkerOptions) {
      return identityMail.worker({
        records,
        clock: options.clock,
        provider: input.provider,
        reconciliation: input.reconciliation,
        preparation: {
          prepare: (request) =>
            options.emailCodes.prepareMail(request, input.renderer),
        },
        workerId: input.workerId,
        ...(input.leaseMilliseconds === undefined
          ? {}
          : { leaseMilliseconds: input.leaseMilliseconds }),
        ...(input.baseRetryMilliseconds === undefined
          ? {}
          : { baseRetryMilliseconds: input.baseRetryMilliseconds }),
        ...(input.acceptedCallbackMilliseconds === undefined
          ? {}
          : {
              acceptedCallbackMilliseconds: input.acceptedCallbackMilliseconds,
            }),
        ...(input.classifyFailure === undefined
          ? {}
          : { classifyFailure: input.classifyFailure }),
      });
    },
    applyAuthenticatedCallback(callback: AuthenticatedMailCallback) {
      return identityMail.applyAuthenticatedCallback(
        records,
        callback,
        options.clock,
      );
    },
    acknowledgeTerminal(acknowledgement: AcknowledgeTerminalMail) {
      return identityMail.acknowledgeTerminal(records, acknowledgement);
    },
    sweep(input: SweepTerminalMailOptions) {
      return identityMail.sweep(records, input);
    },
  });
}

export type {
  AcknowledgeTerminalMail,
  AuthenticatedMailCallback,
  MailPageOptions,
  MailProvider,
  MailReconciliationPort,
  MailWorker,
  SweepTerminalMailOptions,
  SweepTerminalMailResult,
};
