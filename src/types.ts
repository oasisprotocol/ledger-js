import Transport from "@ledgerhq/hw-transport";

export type { Transport };

// @ledgerhq/hw-transport has an awful TransportStatusError type
export interface TransportStatusError extends Error {
  statusCode: number;
  statusText: "UNKNOWN_ERROR";
}

export type DerivationPath = number[];

export interface App {
  transport: Transport;
}

export type Response<T> =
  T & {
    return_code: number;
    error_message: string;
  } | {
    return_code: number;
    error_message: string;
  };

export type AsyncResponse<T> = Promise<Response<T>>;
