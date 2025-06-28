import * as jspb from 'google-protobuf'



export class CompileAndRunRequest extends jspb.Message {
  getSource(): string;
  setSource(value: string): CompileAndRunRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CompileAndRunRequest.AsObject;
  static toObject(includeInstance: boolean, msg: CompileAndRunRequest): CompileAndRunRequest.AsObject;
  static serializeBinaryToWriter(message: CompileAndRunRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CompileAndRunRequest;
  static deserializeBinaryFromReader(message: CompileAndRunRequest, reader: jspb.BinaryReader): CompileAndRunRequest;
}

export namespace CompileAndRunRequest {
  export type AsObject = {
    source: string,
  }
}

export class CompileAndRunResponse extends jspb.Message {
  getCompileError(): CompilationError | undefined;
  setCompileError(value?: CompilationError): CompileAndRunResponse;
  hasCompileError(): boolean;
  clearCompileError(): CompileAndRunResponse;

  getRuntimeError(): RuntimeError | undefined;
  setRuntimeError(value?: RuntimeError): CompileAndRunResponse;
  hasRuntimeError(): boolean;
  clearRuntimeError(): CompileAndRunResponse;

  getRunEvent(): ProbeEvent | undefined;
  setRunEvent(value?: ProbeEvent): CompileAndRunResponse;
  hasRunEvent(): boolean;
  clearRunEvent(): CompileAndRunResponse;

  getCompileAndRunOneofCase(): CompileAndRunResponse.CompileAndRunOneofCase;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CompileAndRunResponse.AsObject;
  static toObject(includeInstance: boolean, msg: CompileAndRunResponse): CompileAndRunResponse.AsObject;
  static serializeBinaryToWriter(message: CompileAndRunResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CompileAndRunResponse;
  static deserializeBinaryFromReader(message: CompileAndRunResponse, reader: jspb.BinaryReader): CompileAndRunResponse;
}

export namespace CompileAndRunResponse {
  export type AsObject = {
    compileError?: CompilationError.AsObject,
    runtimeError?: RuntimeError.AsObject,
    runEvent?: ProbeEvent.AsObject,
  }

  export enum CompileAndRunOneofCase { 
    COMPILE_AND_RUN_ONEOF_NOT_SET = 0,
    COMPILE_ERROR = 1,
    RUNTIME_ERROR = 2,
    RUN_EVENT = 3,
  }
}

export class CompilationError extends jspb.Message {
  getErrorMessage(): string;
  setErrorMessage(value: string): CompilationError;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CompilationError.AsObject;
  static toObject(includeInstance: boolean, msg: CompilationError): CompilationError.AsObject;
  static serializeBinaryToWriter(message: CompilationError, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CompilationError;
  static deserializeBinaryFromReader(message: CompilationError, reader: jspb.BinaryReader): CompilationError;
}

export namespace CompilationError {
  export type AsObject = {
    errorMessage: string,
  }
}

export class RuntimeError extends jspb.Message {
  getErrorMessage(): string;
  setErrorMessage(value: string): RuntimeError;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): RuntimeError.AsObject;
  static toObject(includeInstance: boolean, msg: RuntimeError): RuntimeError.AsObject;
  static serializeBinaryToWriter(message: RuntimeError, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): RuntimeError;
  static deserializeBinaryFromReader(message: RuntimeError, reader: jspb.BinaryReader): RuntimeError;
}

export namespace RuntimeError {
  export type AsObject = {
    errorMessage: string,
  }
}

export class ProbeEvent extends jspb.Message {
  getRunqStatusEvent(): RunqStatusEvent | undefined;
  setRunqStatusEvent(value?: RunqStatusEvent): ProbeEvent;
  hasRunqStatusEvent(): boolean;
  clearRunqStatusEvent(): ProbeEvent;

  getProbeEventOneofCase(): ProbeEvent.ProbeEventOneofCase;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ProbeEvent.AsObject;
  static toObject(includeInstance: boolean, msg: ProbeEvent): ProbeEvent.AsObject;
  static serializeBinaryToWriter(message: ProbeEvent, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): ProbeEvent;
  static deserializeBinaryFromReader(message: ProbeEvent, reader: jspb.BinaryReader): ProbeEvent;
}

export namespace ProbeEvent {
  export type AsObject = {
    runqStatusEvent?: RunqStatusEvent.AsObject,
  }

  export enum ProbeEventOneofCase { 
    PROBE_EVENT_ONEOF_NOT_SET = 0,
    RUNQ_STATUS_EVENT = 1,
  }
}

export class RunqStatusEvent extends jspb.Message {
  getProcId(): number;
  setProcId(value: number): RunqStatusEvent;

  getCurrentPc(): InterpretedPC | undefined;
  setCurrentPc(value?: InterpretedPC): RunqStatusEvent;
  hasCurrentPc(): boolean;
  clearCurrentPc(): RunqStatusEvent;

  getRunqEntriesList(): Array<RunqEntry>;
  setRunqEntriesList(value: Array<RunqEntry>): RunqStatusEvent;
  clearRunqEntriesList(): RunqStatusEvent;
  addRunqEntries(value?: RunqEntry, index?: number): RunqEntry;

  getRunnext(): RunqEntry | undefined;
  setRunnext(value?: RunqEntry): RunqStatusEvent;
  hasRunnext(): boolean;
  clearRunnext(): RunqStatusEvent;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): RunqStatusEvent.AsObject;
  static toObject(includeInstance: boolean, msg: RunqStatusEvent): RunqStatusEvent.AsObject;
  static serializeBinaryToWriter(message: RunqStatusEvent, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): RunqStatusEvent;
  static deserializeBinaryFromReader(message: RunqStatusEvent, reader: jspb.BinaryReader): RunqStatusEvent;
}

export namespace RunqStatusEvent {
  export type AsObject = {
    procId: number,
    currentPc?: InterpretedPC.AsObject,
    runqEntriesList: Array<RunqEntry.AsObject>,
    runnext?: RunqEntry.AsObject,
  }
}

export class InterpretedPC extends jspb.Message {
  getFile(): string;
  setFile(value: string): InterpretedPC;

  getLine(): number;
  setLine(value: number): InterpretedPC;

  getFunc(): string;
  setFunc(value: string): InterpretedPC;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): InterpretedPC.AsObject;
  static toObject(includeInstance: boolean, msg: InterpretedPC): InterpretedPC.AsObject;
  static serializeBinaryToWriter(message: InterpretedPC, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): InterpretedPC;
  static deserializeBinaryFromReader(message: InterpretedPC, reader: jspb.BinaryReader): InterpretedPC;
}

export namespace InterpretedPC {
  export type AsObject = {
    file: string,
    line: number,
    func: string,
  }
}

export class RunqEntry extends jspb.Message {
  getGoId(): number;
  setGoId(value: number): RunqEntry;

  getExecutionContext(): InterpretedPC | undefined;
  setExecutionContext(value?: InterpretedPC): RunqEntry;
  hasExecutionContext(): boolean;
  clearExecutionContext(): RunqEntry;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): RunqEntry.AsObject;
  static toObject(includeInstance: boolean, msg: RunqEntry): RunqEntry.AsObject;
  static serializeBinaryToWriter(message: RunqEntry, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): RunqEntry;
  static deserializeBinaryFromReader(message: RunqEntry, reader: jspb.BinaryReader): RunqEntry;
}

export namespace RunqEntry {
  export type AsObject = {
    goId: number,
    executionContext?: InterpretedPC.AsObject,
  }
}

