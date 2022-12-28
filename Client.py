namespace EpiSource.Unblocker.Hosting {
    public enum DebugMode {
        None,
        Console,
        Debugger
    }
}

namespace EpiSource.Unblocker.Hosting {
    public enum ForcedCancellationMode {
        /// <summary>
        /// The task is marked cancelled if it didn't respond to the cancellation request within the given timeout.
        /// Any awaiters continue immediately after timeout. Cleanup is then performed asynchronously after forced
        /// cancellation. Cleanup starts with an attempt to stop the AppDomain that used to execute the task. If this
        /// fails within a system defined timeout (usually a couple of seconds), the associated worker process is
        /// killed. Unloading the AppDomain may fail if the task was running native code.
        /// </summary>
        /// <remarks>
        /// This is the default cancellation mode. It fits all tasks known to execute only managed code. It is also
        /// recommend for tasks executing native code, as long as the native code being still alive after forced
        /// cancellation is known not to block any resources or cause other side-effects.
        /// </remarks>
        CleanupAfterCancellation,
        
        /// <summary>
        /// The task is given a timeout of `cancellationTimeout / 2` to fulfill the cancellation request.  If the task
        /// fails to respond in time, an attempt is made to unload the AppDomain executing the task. If that fails
        /// within the other half of the cancellation timeout, the worker process is killed.
        /// The task is marked cancelled when the AppDomain was unloaded successfully or the worker process was killed.
        /// Any awaiters continue not before the task has been fully shutdown.
        /// </summary>
        /// <remarks>
        /// This cancellation mode fits all applications, that require the task to be fully stopped before awaiters
        /// continue executing. This mode should be considered when the task is invoking native code that blocks
        /// shared resources.
        /// </remarks>
        CleanupBeforeCancellation,
        
        /// <summary>
        /// The task is given a timeout of `cancellationTimeout / 2` to fulfill the cancellation request. If the task
        /// fails to respond in time,  the worker process is killed.
        /// Any awaiters continue not before the task has been fully shutdown or the worker process was killed.
        /// </summary>
        /// <remarks>
        /// This cancellation mode fits all applications invoking mostly native code, that are likely to react on
        /// cancellation in time.
        /// </remarks>
        KillOnCancellationTimeout,
        
        /// <summary>
        /// The worker process executing the task is killed immediately on cancellation request. Any awaiters continue
        /// after the process was canceled.
        /// </summary>
        /// <remarks>
        /// This cancellation mode fits all applications invoking only native code and that are known not to react
        /// on cancellation requests.
        /// </remarks>
        KillImmediately
    }
}

using System;
using System.Security.Permissions;
using System.Security.Policy;

namespace EpiSource.Unblocker.Hosting {
    public static class HostingExtensions {
        public static StrongName GetStrongNameOfAssembly(this Type t) {
            var assemblyName = t.Assembly.GetName();
            var pubKeyBytes = assemblyName.GetPublicKey();
            if (pubKeyBytes == null || pubKeyBytes.Length == 0) {
                return null;
            }

            return new StrongName(
                new StrongNamePublicKeyBlob(pubKeyBytes), assemblyName.Name, assemblyName.Version);
        }

        public static StrongName[] GetStrongNameOfAssemblyAsArray(this Type t) {
            var sn = t.GetStrongNameOfAssembly();
            return sn != null ? new[] {sn} : new StrongName[] { };
        }
        
        public static void InvokeEvent<T>(this T eventHandler, Action<T> handlerInvocation) {
            if (eventHandler != null) {
                handlerInvocation(eventHandler);
            }
        }
    }
}


using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.Serialization;
using System.Threading;

namespace EpiSource.Unblocker.Hosting {
    [Serializable]
    public sealed partial class InvocationRequest {
        private readonly MethodInfo method;
        private readonly object target;
        private readonly IList<object> args;

        private InvocationRequest(MethodInfo method, object target, IList<object> args) {
            this.method = method;
            this.target = target;
            this.args = new ReadOnlyCollection<object>(args);
        }

        public MethodInfo Method {
            get { return this.method; }
        }

        public object Target {
            get { return this.target; }
        }

        public IList<object> Arguments {
            get { return this.args; }
        }

        public PortableInvocationRequest ToPortableInvocationRequest() {
            return new PortableInvocationRequest(this);
        }

        public object Invoke(CancellationToken token) {
            var argsArray = this.Arguments.Select(arg => arg is CancellationTokenMarker ? token : arg).ToArray();
            try {
                return this.Method.Invoke(this.Target, argsArray);
            } catch (TargetInvocationException e) {
                ExceptionDispatchInfo.Capture(e.InnerException).Throw();
                throw;
            }
        }
        
        public static InvocationRequest FromExpression<T>(Expression<Func<CancellationToken, T>> invocation) {
            return FromExpression((LambdaExpression) invocation);
        }

        public static InvocationRequest FromExpression(Expression<Action<CancellationToken>> invocation) {
            return FromExpression((LambdaExpression) invocation);
        }

        private static InvocationRequest FromExpression(LambdaExpression invocation) {
            if (invocation == null) {
                throw new ArgumentNullException("invocation");
            }

            if (invocation.Parameters.Count != 1 
                    || !typeof(CancellationToken).IsAssignableFrom(invocation.Parameters[0].Type)) {
                throw new ArgumentException(
                    "Only parameter of invocation lambda must be of type CancellationToken, but was different.",
                    "invocation");
            }

            var methodCall = invocation.Body as MethodCallExpression;
            if (methodCall == null) {
                var unaryBody = invocation.Body as UnaryExpression;
                if (unaryBody != null && unaryBody.NodeType == ExpressionType.Convert) {
                    methodCall = unaryBody.Operand as MethodCallExpression;
                }
            }

            if (methodCall == null) {
                throw new ArgumentException(
                    "Invalid lambda expression. Only simple method invocation supported. E.g. `t => this.exec(...)`.",
                    "invocation");
            }

            var obj = ResolveExpression(methodCall.Object, invocation.Parameters[0]);
            var args = ResolveArguments(methodCall, invocation.Parameters[0]);
            return new InvocationRequest(methodCall.Method, obj, args);
        }

        private static IList<object> ResolveArguments(
            MethodCallExpression callExpression, ParameterExpression tokenExpression
        ) {
            var resolvedArgs = new List<object>(callExpression.Arguments.Count);

            // ReSharper disable once LoopCanBeConvertedToQuery
            foreach (var arg in callExpression.Arguments) {
                resolvedArgs.Add(ResolveExpression(arg, tokenExpression));
            }
            return resolvedArgs;
        }

        private static object ResolveExpression(
            Expression anyExpression, ParameterExpression tokenExpression
        ) {
            if (anyExpression == null) {
                return null;
            }

            var lambda = Expression.Lambda(anyExpression, tokenExpression).Compile();

            var obj = lambda.DynamicInvoke(new CancellationToken());
            if (obj is CancellationToken) {
                return new CancellationTokenMarker();
            }
            if (!IsSerializable(obj)) {
                throw new SerializationException(
                    string.Format("Evaluation result of expression `{0}` ({1} = {2}) is not serializable.",
                        anyExpression, obj.GetType().FullName, obj));
            }

            return obj;
        }

        private static bool IsSerializable(object obj) {
            return obj == null || IsSerializableType(obj.GetType());
        }

        private static bool IsSerializableType(Type t) {
            return  typeof(ISerializable).IsAssignableFrom(t) ||
                    typeof(string).IsAssignableFrom(t)        ||
                    typeof(void) == t                         ||
                    t.IsSerializable                          ||
                    t.IsPrimitive;
        }
    }
}


using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization.Formatters.Binary;

namespace EpiSource.Unblocker.Hosting {
    public partial class InvocationRequest {
        [Serializable]
        public sealed class PortableInvocationRequest {
            // Actual invocation request stored as binary data to prevent remoting framework from automatically
            // deserializing it: This required loading all referenced assemblies in the AppDomain running the server
            // application. However, assemblies should be loaded in a task specific  AppDomain.
            private readonly byte[] serializedInvocationRequest;

            private readonly AssemblyReferencePool referencePool;
            private readonly string methodName;
            private readonly string applicationBase;

            public PortableInvocationRequest(InvocationRequest request) {
                if (request == null) {
                    throw new ArgumentNullException("request");
                }
                
                this.serializedInvocationRequest = Serialize(request);
                this.referencePool = new AssemblyReferencePool(AppDomain.CurrentDomain);
                this.methodName = request.Method.DeclaringType.FullName + "." + request.Method.Name;
                this.applicationBase = AppDomain.CurrentDomain.BaseDirectory;
            }

            public string MethodName {
                get { return this.methodName; }
            }

            public string ApplicationBase {
                get { return this.applicationBase; }
            }

            public InvocationRequest ToInvocationRequest() {
                this.referencePool.AttachToDomain(AppDomain.CurrentDomain);
                try {
                    return Deserialize(this.serializedInvocationRequest);
                } finally {
                    this.referencePool.DetachFromDomain(AppDomain.CurrentDomain);
                }
            }

            private static byte[] Serialize(InvocationRequest request) {
                var binFormatter = new BinaryFormatter();
                var bufferStream = new MemoryStream();
                binFormatter.Serialize(bufferStream, request);
                return bufferStream.ToArray();
            }

            private static InvocationRequest Deserialize(byte[] serializedRequest) {
                var binFormatter = new BinaryFormatter();
                var serializedStream = new MemoryStream(serializedRequest);
                return (InvocationRequest) binFormatter.Deserialize(serializedStream);
            }
        }

        [Serializable]
        private sealed class AssemblyReferencePool {
            private readonly IDictionary<string, string> nameToLocationMap;

            public AssemblyReferencePool(AppDomain hostDomain) {
                // note: it's possible for two assemblies with same name to be loaded (different location!)
                // -> choose first
                this.nameToLocationMap = hostDomain.GetAssemblies()
                                                   .Where(a => !a.IsDynamic && File.Exists(a.Location))
                                                   .GroupBy(a => a.FullName)
                                                   .Select(g => g.First())
                                                   .ToDictionary(a => a.FullName, a => a.Location);
            }

            public void AttachToDomain(AppDomain target) {
                target.AssemblyResolve += this.ResolveAssembly;
                target.ReflectionOnlyAssemblyResolve += this.ResolveAssemblyReflectionOnly;
            }

            public void DetachFromDomain(AppDomain target) {
                target.AssemblyResolve -= this.ResolveAssembly;
                target.ReflectionOnlyAssemblyResolve -= this.ResolveAssemblyReflectionOnly;
            }

            public string GetAssemblyLocation(string fullName) {
                return this.nameToLocationMap.ContainsKey(fullName) ? this.nameToLocationMap[fullName] : null;
            }

            private Assembly ResolveAssembly(object sender, ResolveEventArgs args) {
                var location = this.GetAssemblyLocation(args.Name);
                return location != null ? Assembly.LoadFile(location) : null;
            }

            private Assembly ResolveAssemblyReflectionOnly(object sender, ResolveEventArgs args) {
                var location = this.GetAssemblyLocation(args.Name);
                return location != null ? Assembly.ReflectionOnlyLoadFrom(location) : null;
            }
        }

        [Serializable]
        private struct CancellationTokenMarker { }
    }
}



using System;

namespace EpiSource.Unblocker.Hosting {
    [Serializable]
    public sealed class TaskSucceededEventArgs : EventArgs {
        public TaskSucceededEventArgs(object result) {
            this.Result = result;
        }

        public object Result { get; private set; }
    }

    [Serializable]
    public sealed class TaskFailedEventArgs : EventArgs {
        public TaskFailedEventArgs(Exception e) {
            this.Exception = e;
        }

        public Exception Exception { get; private set; }
    }

    [Serializable]
    public sealed class TaskCanceledEventArgs : EventArgs {

        public TaskCanceledEventArgs(bool canceledVoluntarily) {
            this.CanceledVoluntarily = canceledVoluntarily;
        }
        
        public bool CanceledVoluntarily { get; private set; }
    }
}




using System;

namespace EpiSource.Unblocker.Hosting {
    public class TaskCrashedException : Exception {
        public TaskCrashedException() 
            : base("The worker process executing the current task crashed or was forced to stop.") { }
    }
}


using System;
using System.Linq.Expressions;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Lifetime;
using System.Security;
using System.Threading;
using System.Threading.Tasks;

namespace EpiSource.Unblocker.Hosting {
    [Serializable]
    public sealed class WorkerStateChangedEventArgs : EventArgs {
        public WorkerStateChangedEventArgs(WorkerClient.State state) {
            this.State = state;
        }
        
        public WorkerClient.State State { get; private set; }
    }
    
    public sealed class WorkerClient : MarshalByRefObject, IDisposable{
        public enum State {
            Idle,
            Busy,
            Cleanup,
            Dying,
            Dead,
        }
        
        private readonly object stateLock = new object();
        private readonly ClientSponsor proxyLifetimeSponsor = new ClientSponsor();
        private readonly string id;
        private readonly WorkerProcess process;
        private readonly IWorkerServer serverProxy;
        
        private volatile State state = State.Idle;
        private TaskCompletionSource<object> activeTcs;

        public WorkerClient(WorkerProcess process, IWorkerServer serverProxy) {
            this.process = process;
            this.id = "[client:" + process.Id + "]";
            
            this.serverProxy = serverProxy;
            if (this.serverProxy is MarshalByRefObject) {
                this.proxyLifetimeSponsor.Register((MarshalByRefObject)this.serverProxy);
            }

            this.process.ProcessDeadEvent += this.OnProcessDead;

            this.serverProxy.ServerDyingEvent += this.OnServerDying;
            this.serverProxy.ServerReadyEvent += this.OnServerReady;
            this.serverProxy.TaskFailedEvent += this.OnRemoteTaskFailed;
            this.serverProxy.TaskCanceledEvent += this.OnRemoteTaskCanceled;
            this.serverProxy.TaskSucceededEvent += this.OnRemoteTaskSucceeded;
        }

        // Important: don't raise when holding the state lock!
        public event EventHandler<WorkerStateChangedEventArgs> CurrentStateChangedEvent;

        public State CurrentState {
            get {
                return this.state;
            }
        }
        
        public async Task<T> InvokeRemotely<T>(
            Expression<Func<CancellationToken, T>> invocation, CancellationToken ct,
            TimeSpan cancellationTimeout, ForcedCancellationMode forcedCancellationMode, SecurityZone securityZone,
            WorkerProcessRef workerProcessRef
        ) {
            var request = InvocationRequest.FromExpression(invocation);
            return (T) await this.InvokeRemotely(
                                     request, ct, cancellationTimeout, forcedCancellationMode, securityZone,
                                     workerProcessRef)
                                 .ConfigureAwait(false);
        }

        public async Task InvokeRemotely(
            Expression<Action<CancellationToken>> invocation, CancellationToken ct,
            TimeSpan cancellationTimeout, ForcedCancellationMode forcedCancellationMode,
            SecurityZone securityZone, WorkerProcessRef workerProcessRef
        ) {
            var request = InvocationRequest.FromExpression(invocation);
            await this.InvokeRemotely(
                          request, ct, cancellationTimeout, forcedCancellationMode, securityZone, workerProcessRef)
                      .ConfigureAwait(false);
        }

        public override string ToString() {
            return this.id;
        }

        private Task<object> InvokeRemotely(
            InvocationRequest request, CancellationToken ct, TimeSpan cancellationTimeout, 
            ForcedCancellationMode forcedCancellationMode, SecurityZone securityZone, WorkerProcessRef workerProcessRef
        ) {
            const State nextState = State.Busy;
            
            lock (this.stateLock) {               
                if (this.CurrentState != State.Idle) {
                    throw new InvalidOperationException(
                        "Worker process is not ready. Current state is: " + this.CurrentState);
                }

                if (!this.process.IsAlive) {
                    this.OnProcessDead(this, EventArgs.Empty);
                    throw new InvalidOperationException("Worker process not alive / crashed.");
                }
                
                this.state = nextState;
                this.activeTcs = new TaskCompletionSource<object>();

                if (workerProcessRef != null) {
                    workerProcessRef.WorkerProcess = this.process.Process;
                }
                
                // this is the latest time to check whether the task has already been cancelled, before actually
                // starting the task!
                if (ct.IsCancellationRequested) {
                    this.activeTcs.TrySetCanceled();
                    this.activeTcs = null;
                    return this.activeTcs.Task;
                }
            }
            
            // outside lock!
            this.OnCurrentStateChanged(nextState);
            
            ct.Register(() => {
                try {
                    this.serverProxy.Cancel(cancellationTimeout, forcedCancellationMode);
                } catch (RemotingException) {
                    if (!this.process.IsAlive) {
                        // worker killed itself or crashed: ignore!
                        return;
                    }

                    throw;
                }
            });
            this.serverProxy.InvokeAsync(request.ToPortableInvocationRequest(), securityZone);

            // Calling Cancel(..) on the server is only handled if there's a invocation request being handled!
            // there's the chance that task was canceled before it was actually started. It might have happened
            // before registering the cancel callback, as well.
            // At this point we now for sure, that the task has been started!
            if (ct.IsCancellationRequested) {
                this.serverProxy.Cancel(cancellationTimeout, forcedCancellationMode);
            }
            
            return this.activeTcs.Task;
        }

        // do not hold state lock when invoking this!
        private void OnCurrentStateChanged(State nextState) {
            var handler = this.CurrentStateChangedEvent;
            if (handler != null) {
                this.CurrentStateChangedEvent(this, new WorkerStateChangedEventArgs(nextState));
            }
        }

        private void OnRemoteTaskCanceled(object sender, EventArgs args) {
            this.OnRemoteTaskDone(tcs => tcs.TrySetCanceled());
        }
        private void OnRemoteTaskSucceeded(object sender, TaskSucceededEventArgs args) {
            this.OnRemoteTaskDone(tcs => tcs.TrySetResult(args.Result));
        }

        private void OnRemoteTaskFailed(object sender, TaskFailedEventArgs args) {
            this.OnRemoteTaskDone(tcs => tcs.TrySetException(args.Exception));
        }

        private void OnRemoteTaskDone(Action<TaskCompletionSource<object>> tcsUpdate) {
            const State nextState = State.Cleanup;
            
            lock (this.stateLock) {
                this.state = nextState;
                
                tcsUpdate(this.activeTcs);
                this.activeTcs = null;
            }
            
            // outside lock!
            this.OnCurrentStateChanged(nextState);
        }

        private void OnServerDying(object sender, EventArgs e) {
            const State nextState = State.Dying;
            
            lock (this.stateLock) {
                this.state = nextState;
            }
            
            // outside lock!
            this.OnCurrentStateChanged(nextState);
        }

        private void OnProcessDead(object sender, EventArgs e) {
            const State nextState = State.Dead;
            
            lock (this.stateLock) {
                if (this.activeTcs != null) {
                    if (this.state == State.Dying) {
                        this.activeTcs.TrySetCanceled();
                    } else {
                        this.activeTcs.TrySetException(new TaskCrashedException());
                    }

                    this.activeTcs = null;
                }
                
                this.state = nextState;
            }
            
            // outside lock!
            this.OnCurrentStateChanged(nextState);
            this.Dispose();
        }

        private void OnServerReady(object sender, EventArgs e) {
            const State nextState = State.Idle;
            
            lock (this.stateLock) {
                // should never happen - nevertheless give the best to handle this
                if (this.activeTcs != null) {
                    this.activeTcs.TrySetCanceled();
                    this.activeTcs = null;
                }
                
                this.state = nextState;
            }
            
            // outside lock!
            this.OnCurrentStateChanged(nextState);
        }

        public void Dispose() {
            this.Dispose(true);
        }

        private /*protected virtual*/ void Dispose(bool disposing) {
            if (disposing && this.state != State.Dead) {
                lock (this.stateLock) {
                    this.state = State.Dead;
                    
                    this.process.ProcessDeadEvent -= this.OnProcessDead;

                    this.serverProxy.ServerDyingEvent -= this.OnServerDying;
                    this.serverProxy.ServerReadyEvent -= this.OnServerReady;
                    this.serverProxy.TaskFailedEvent -= this.OnRemoteTaskFailed;
                    this.serverProxy.TaskCanceledEvent -= this.OnRemoteTaskCanceled;
                    this.serverProxy.TaskSucceededEvent -= this.OnRemoteTaskSucceeded;
                    
                    this.proxyLifetimeSponsor.Close();
                    this.process.Dispose();
                }
            }
        }
    }
}


using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

// ReSharper disable IdentifierTypo

namespace EpiSource.Unblocker.Hosting {
    public sealed class WorkerProcess : IDisposable {
        // ReSharper disable once MemberCanBePrivate.Global
        public static readonly TimeSpan StartupTimeout = new TimeSpan(0, 0, 10);
        
        private readonly object processLock = new object();
        private bool disposed;
        private Process process;
        
        // ReSharper disable once MemberCanBePrivate.Global
        public static EventWaitHandle CreateWaitForProcessReadyHandle(Guid ipcguid) {
            return CreateWaitForProcessReadyHandle(ipcguid.ToString());
        }

        public static EventWaitHandle CreateWaitForProcessReadyHandle(string ipcguid) {
            return new EventWaitHandle(false, EventResetMode.ManualReset, 
                typeof(WorkerServerHost).FullName + ":" + ipcguid);
        }

        public event EventHandler ProcessDeadEvent;

        public bool IsAlive {
            get {
                var p = this.process;

                try {
                    return p != null && !p.HasExited;
                } catch (InvalidOperationException) { } catch (Win32Exception) { }

                return false;
            }
        }

        public int Id {
            get {
                var p = this.process;
                if (p == null) {
                    throw new InvalidOperationException("Id has not been set / process not active.");
                }

                return p.Id;
            }
        }

        public Process Process {
            get { return this.process; }
        }

        [SuppressMessage("ReSharper", "StringLiteralTypo")]
        public WorkerClient Start(DebugMode debug = DebugMode.None) {
            lock (this.processLock) {
                if (this.disposed) {
                    throw new ObjectDisposedException("WorkerProcess has been disposed.");
                }
                if (this.process != null) {
                    throw new InvalidOperationException("Process already started.");
                }

                var ipcguid = Guid.NewGuid();

                var redirectConsole = debug != DebugMode.None;
                this.process = new Process {
                    StartInfo = {
                        #if useInstallUtil
                        FileName = GetInstallUtilLocation(),
                        #else
                        FileName = bootstrapAssemblyPath.Value,
                        #endif
                        
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        WorkingDirectory = typeof(WorkerServerHost).Assembly.Location + @"\..",
                        Arguments = string.Format(CultureInfo.InvariantCulture,
                            "/LogFile= /notransaction /ipcguid={0} /parentpid={1} /debug={2} {3}",
                            ipcguid, Process.GetCurrentProcess().Id, debug, typeof(WorkerServerHost).Assembly.Location),
                        RedirectStandardOutput = redirectConsole,
                        RedirectStandardError = redirectConsole
                    },
                    EnableRaisingEvents = true
                };

                this.process.Exited += (sender, args) => {
                    var handler = this.ProcessDeadEvent;
                    if (handler != null) {
                        handler(this, args);
                    }
                };
                
                if (redirectConsole) {
                    this.process.OutputDataReceived += (s, e) => Console.WriteLine(e.Data);
                    this.process.ErrorDataReceived += (s, e) => Console.WriteLine(e.Data);
                }

                // Start process and wait for it to be ready
                var waitForProcessReadyHandle = CreateWaitForProcessReadyHandle(ipcguid);
                this.process.Start();

                if (redirectConsole) {
                    this.process.BeginOutputReadLine();
                    this.process.BeginErrorReadLine();
                }

                var timeoutMs = debug == DebugMode.Debugger ? -1 : (int)StartupTimeout.TotalMilliseconds;
                var isReady = waitForProcessReadyHandle.WaitOne(timeoutMs, false);
                
                if (!isReady) {
                    try {
                        this.process.Kill();
                    } catch (Exception) {
                        // already did my best - nothing more left to do
                    }

                    throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture,
                        "Failed to start unblocker process. Wasn't ready within {0}s!",
                        StartupTimeout.TotalSeconds));
                }

                var server = WorkerServerClientSideProxy.ConnectToWorkerServer(ipcguid);
                return new WorkerClient(this, server);
            }
        }
        
        public void Dispose() {
            lock (this.processLock) {
                this.Dispose(true);
                GC.SuppressFinalize(this);
            }
        }

        // ReSharper disable once UnusedParameter.Local
        private /*protected virtual*/ void Dispose(bool disposing) {
            if (!this.disposed) {
                this.disposed = true;

                if (this.process != null) {
                    try {
                        // Dispose locks; finalizer should not
                        // ReSharper disable once InconsistentlySynchronizedField
                        this.process.Kill();
                    } catch (InvalidOperationException) {
                        // has already exited
                    }

                    // ReSharper disable once InconsistentlySynchronizedField
                    this.process.Dispose();
                    // ReSharper disable once InconsistentlySynchronizedField
                    this.process = null;
                }
            }
        }

        ~WorkerProcess() {
            this.Dispose(false);
        }
        
        private static string GetInstallUtilLocation() {
            return Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "InstallUtil.exe");
        }

        #if !useInstallUtil
        private static Lazy<string> bootstrapAssemblyPath = new Lazy<string>(WorkerServerHost.CreateBootstrapAssembly);
        #endif
        
    }

}


using System;
using System.Diagnostics;

namespace EpiSource.Unblocker.Hosting {
    public sealed class WorkerProcessRef {
        private Process workerProcess;

        public Process WorkerProcess {
            get {
                return this.workerProcess;
            }
            set {
                if (this.workerProcess != null) {
                    throw new InvalidOperationException("Value already set!");
                }

                this.workerProcess = value;
            }
        }
    }
}


using System;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Remoting.Lifetime;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Policy;
using System.Threading;
using System.Threading.Tasks;

namespace EpiSource.Unblocker.Hosting {
    public interface IWorkerServer : IDisposable {
        event EventHandler<TaskSucceededEventArgs> TaskSucceededEvent;
        event EventHandler<TaskCanceledEventArgs> TaskCanceledEvent;
        event EventHandler<TaskFailedEventArgs> TaskFailedEvent;
        event EventHandler ServerDyingEvent;
        event EventHandler ServerReadyEvent;

        void Cancel(TimeSpan cancelTimeout, ForcedCancellationMode forcedCancellationMode);

        void InvokeAsync(InvocationRequest.PortableInvocationRequest invocationRequest, SecurityZone securityZone);
    }

    public sealed partial class WorkerServer : MarshalByRefObject, IWorkerServer {
        private readonly object stateLock = new object();
        private readonly string serverId = "[server:" + Process.GetCurrentProcess().Id + "]";
        private readonly ClientSponsor proxyLifetimeSponsor = new ClientSponsor();
        private volatile bool isReady = true;
        private volatile TaskRunner activeRunner;
        private volatile AppDomain activeRunnerDomain;
        private volatile CancellationTokenSource cleanupTaskCts;

        public event EventHandler<TaskSucceededEventArgs> TaskSucceededEvent;
        public event EventHandler<TaskCanceledEventArgs> TaskCanceledEvent;
        public event EventHandler<TaskFailedEventArgs> TaskFailedEvent;
        public event EventHandler ServerDyingEvent;
        public event EventHandler ServerReadyEvent;


        public void Cancel(
            TimeSpan cancelTimeout, ForcedCancellationMode forcedCancellationMode
        ) {
            if (forcedCancellationMode == ForcedCancellationMode.KillImmediately) {
                this.CommitSuicide();
            }
            
            lock (this.stateLock) {
                if (this.activeRunner != null && this.cleanupTaskCts == null) {
                    this.cleanupTaskCts = new CancellationTokenSource();
                    
                    // ReSharper disable once UnusedVariable
                    var ensureCanceledTask = this.EnsureCanceled(
                        cancelTimeout, forcedCancellationMode, this.cleanupTaskCts.Token);
                    
                    this.activeRunner.Cancel();
                }
            }
        }

        // returns when invocation is started, but before it returns
        // end of invocation is signaled via TaskCompletionSourceProxy
        public void InvokeAsync(
            InvocationRequest.PortableInvocationRequest invocationRequest, SecurityZone securityZone
        ) {
            if (invocationRequest == null) {
                throw new ArgumentNullException("invocationRequest");
            }

            lock (this.stateLock) {
                if (!this.isReady) {
                    throw new InvalidOperationException(
                        "Not ready: currently executing another task or cleaning up.");
                }
                this.isReady = false;
                

                var zoneEvidence = new Evidence();
                zoneEvidence.AddHostEvidence(new Zone(securityZone));
                var zonePermissions = SecurityManager.GetStandardSandbox(zoneEvidence);

                var taskDomainName = string.Format(CultureInfo.InvariantCulture, "{0}_{1}",
                    invocationRequest.MethodName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

                // ReSharper disable once AssignNullToNotNullAttribute
                this.activeRunnerDomain = AppDomain.CreateDomain(taskDomainName, AppDomain.CurrentDomain.Evidence,
                    new AppDomainSetup {
                        ApplicationBase = invocationRequest.ApplicationBase,
                        LoaderOptimization = LoaderOptimization.MultiDomainHost
                    }, zonePermissions, typeof(WorkerServer).GetStrongNameOfAssemblyAsArray());

                this.activeRunner = (TaskRunner) this.activeRunnerDomain.CreateInstanceFromAndUnwrap(
                    typeof(TaskRunner).Assembly.Location,typeof(TaskRunner).FullName);
                this.activeRunner.Setup();
                
                this.proxyLifetimeSponsor.Register(this.activeRunner);
            }

            Task.Run(() => {
                // this invocation can fail by to ways:
                // 1. forced shutdown of appdomain - ignore silently
                // 2. serialization exception related to type of result - pass to callee
                try {
                    var result = this.activeRunner.InvokeSynchronously(invocationRequest);
                    this.OnRunnerDone(result);
                } catch (SerializationException e) {
                    this.OnRunnerDone(new TaskFailedEventArgs(e));
                } finally {
                    this.Cleanup(true);
                }
            });

            Console.WriteLine(string.Format(
                CultureInfo.InvariantCulture, "{0} Started executing invocation request.",
                this.serverId));
        }

        private void OnRunnerDone(EventArgs result) {
            if (result is TaskSucceededEventArgs) {
                this.OnRunnerDone(this.TaskSucceededEvent,
                    e => e(this, (TaskSucceededEventArgs) result),
                    "SUCCESS");
            } else if (result is TaskCanceledEventArgs) {
                this.OnRunnerDone(this.TaskCanceledEvent,
                    e => e(this, (TaskCanceledEventArgs) result),
                    "CANCELED");
            } else if (result is TaskFailedEventArgs) {
                var failedArgs = result as TaskFailedEventArgs;
                var ex = failedArgs.Exception;

                var msg = "EXCEPTION";
                if (ex != null) {
                    msg += " " + ex.GetType() + " - " + ex.Message;
                }

                this.OnRunnerDone(this.TaskFailedEvent,
                    e => e(this, failedArgs), msg);
            } else {
                throw new ArgumentException("Unknown result type.", "result");
            }
        }

        private void OnRunnerDone<T>(T eventHandler, Action<T> handlerInvocation, string resultMsg) {
            Console.WriteLine(string.Format(
                CultureInfo.InvariantCulture, "{0} Done executing invocation request. Result: {1}",
                this.serverId, resultMsg));

            eventHandler.InvokeEvent(handlerInvocation);
        }


        private async Task EnsureCanceled(
            TimeSpan cancelTimeout, ForcedCancellationMode forcedCancellationMode, CancellationToken ct
        ) {
            if (forcedCancellationMode == ForcedCancellationMode.KillImmediately) {
                this.CommitSuicide();
            }
            
            var asyncCancellation = forcedCancellationMode == ForcedCancellationMode.CleanupAfterCancellation;
            var halfCancelTimeout = TimeSpan.FromMilliseconds(cancelTimeout.TotalMilliseconds / 2);

            try {
                await Task.Delay(asyncCancellation ? cancelTimeout : halfCancelTimeout, ct).ConfigureAwait(false);
            } catch (TaskCanceledException) {
                return;
            }

            if (!asyncCancellation) {
                // ReSharper disable once UnusedVariable
                var cleanupTask = this.CleanupWatchdog(halfCancelTimeout, ct);
            }
            
            this.Cleanup(false, asyncCancellation);
        }

        private async Task CleanupWatchdog(TimeSpan timeout, CancellationToken ct) {
            try {
                await Task.Delay(timeout, ct).ConfigureAwait(false);
                if (!this.isReady) {
                    this.CommitSuicide();
                }
            } catch (TaskCanceledException) {
                // cleanup succeeded within timeout
            }
        }

        // unload appdomain
        private void Cleanup(bool cleanShutdown, bool asyncCancellation = true) {
            lock (this.stateLock) {
                if (this.isReady) {
                    // nothing to cleanup - already clean
                    return;
                }

                if (this.activeRunner != null) {
                    this.proxyLifetimeSponsor.Unregister(this.activeRunner);
                    this.activeRunner = null;
                }
            }

            if (!cleanShutdown) {
                Console.WriteLine(
                    this.serverId + " Failed to cancel task. Going to kill the task. Let's tell.");

                if (asyncCancellation) {
                    this.TaskCanceledEvent.InvokeEvent(
                        e => e(this, new TaskCanceledEventArgs(false)));
                }
            }
            
            try {
                AppDomain runnerDomain;
                lock (this.stateLock) {
                    runnerDomain = this.activeRunnerDomain;
                    this.activeRunnerDomain = null;

                    if (runnerDomain == null) {
                        return;
                    }
                }

                Console.WriteLine(this.serverId + " Going to unload the task's AppDomain.");
                AppDomain.Unload(runnerDomain);
                Console.WriteLine(this.serverId + " Done unloading the task's AppDomain.");
                
                if (!cleanShutdown && !asyncCancellation) {
                    this.TaskCanceledEvent.InvokeEvent(
                        e => e(this, new TaskCanceledEventArgs(false)));
                }

                lock (this.stateLock) {
                    // cleanup task has executed!
                    if (this.cleanupTaskCts != null) {
                        this.cleanupTaskCts.Cancel();
                    }
                    
                    this.activeRunnerDomain = null;
                    this.isReady = true;
                }
                
                this.ServerReadyEvent.InvokeEvent(e => e(this, EventArgs.Empty));
            } catch (CannotUnloadAppDomainException ex) {
                Console.WriteLine(this.serverId + " Failed to unload task's AppDomain: " + ex.Message);
                this.CommitSuicide();
            }
        }

        private void CommitSuicide() {
            Console.WriteLine(this.serverId + " Going to kill myself!");

            // kill current worker in the most robust way possible!
            try {
                this.ServerDyingEvent.InvokeEvent(e => e(this, EventArgs.Empty));
            } catch (Exception ex) {
                // continue on any possible remoting error
                // most likely: remoting error
                
                Console.WriteLine(this.serverId + " Failed to announce suicide: " + ex.Message);
                Console.WriteLine(ex.StackTrace);
            }
            
            try {
                
                Process.GetCurrentProcess().Kill();
            } catch (Exception ex) {
                Console.WriteLine(this.serverId + " Failed to commit suicide: " + ex.Message);
                Console.WriteLine(ex.StackTrace);
                Console.WriteLine(this.serverId + " Client will have to take care of that!");
            }
        }

        public override string ToString() {
            return this.serverId;
        }

        public void Dispose() {
            lock (this.stateLock) {
                this.Dispose(true);
            }
        }

        private /*protected virtual*/ void Dispose(bool disposing) {
            if (disposing) {
                this.Cancel(TimeSpan.FromMilliseconds(50), ForcedCancellationMode.CleanupAfterCancellation);
            }
        }
    }
}


using System;
using System.Threading;

namespace EpiSource.Unblocker.Hosting {
    public partial class WorkerServer {
        // may be used for one invocation only!
        private sealed class TaskRunner : MarshalByRefObject {
            private readonly CancellationTokenSource cts = new CancellationTokenSource();

            public void Setup() {
                // resolve current assembly across load context
                // important if current assembly was loaded from outside the default assembly search path
                AppDomain.CurrentDomain.AssemblyResolve += (s, e) => {
                    if (e.Name == typeof(TaskRunner).Assembly.FullName) {
                        return typeof(TaskRunner).Assembly;
                    }

                    return null;
                };
            }
            
            public void Cancel() {
                this.cts.Cancel();
            }

            public EventArgs InvokeSynchronously(
                InvocationRequest.PortableInvocationRequest portableInvocationRequest
            ) {
                // Important: Calling parent.OnRunner* causes the app domain executing the current runner to be unloaded
                try {
                    this.cts.Token.ThrowIfCancellationRequested();
                    var result = portableInvocationRequest.ToInvocationRequest().Invoke(this.cts.Token);
                    return new TaskSucceededEventArgs(result);
                } catch (OperationCanceledException e) {
                    if (e.CancellationToken == this.cts.Token) {
                        return new TaskCanceledEventArgs(true);
                    } 
                        
                    return new TaskFailedEventArgs(e);
                } catch (Exception e) {
                    return new TaskFailedEventArgs(e);
                }
            }
        }
    }
}


using System;
using System.Collections;
using System.Globalization;
using System.Reflection;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Ipc;
using System.Runtime.Remoting.Lifetime;
using System.Security;

namespace EpiSource.Unblocker.Hosting {
    /// Limit remoting to specific appdomain: Channels cannot be unregistered and ensures that other services
    /// within the application using this library are not exposed by the worker channel.
    public sealed class WorkerServerClientSideProxy : MarshalByRefObject, IWorkerServer {
        private sealed class ProxyDomainSetup : MarshalByRefObject {

            public void Setup() {
                AppDomain.CurrentDomain.AssemblyResolve += ResolveCurrentAssemblyAcrossLoadContext;
                
                // register explicit channel to be compatible with the server side
                // needed when using callbacks
                IDictionary ipcProperties = new Hashtable();
                ipcProperties["name"] = "UnblockerClientChannel";
                ipcProperties["portName"] = Guid.NewGuid().ToString();
                ipcProperties["typeFilterLevel"] = "Full";
                var ipcChannel = new IpcChannel(ipcProperties,
                    new BinaryClientFormatterSinkProvider(ipcProperties, null),
                    new BinaryServerFormatterSinkProvider(ipcProperties, null));
                ChannelServices.RegisterChannel(ipcChannel, false);
            }
        }
        
        private static readonly object proxyDomainLock = new object(); 
        private static AppDomain proxyDomain;
        private static int proxyDomainRefCount;
        
        // Limit remoting to specific appdomain: Channels cannot be unregistered and ensures that other services
        // within the application using this library are not exposed by the worker channel.
        public static WorkerServerClientSideProxy ConnectToWorkerServer(Guid ipcguid) {
            var t = typeof(WorkerServerClientSideProxy);
            var remotingDomainDame = string.Format(CultureInfo.InvariantCulture, "{0}_{1}",
                typeof(WorkerServerClientSideProxy).Name, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            
            lock (proxyDomainLock) {
                if (proxyDomainRefCount == 0) {
                    var remotingDomain = AppDomain.CreateDomain(remotingDomainDame, AppDomain.CurrentDomain.Evidence,
                        new AppDomainSetup {
                            ApplicationBase = AppDomain.CurrentDomain.BaseDirectory,
                            LoaderOptimization = LoaderOptimization.MultiDomainHost
                        },
                        AppDomain.CurrentDomain.PermissionSet, t.GetStrongNameOfAssemblyAsArray());
                    
                    proxyDomain = remotingDomain;
                    proxyDomainRefCount++;

                    AppDomain.CurrentDomain.AssemblyResolve += ResolveCurrentAssemblyAcrossLoadContext;
                    
                    // Important: Load current assembly based on path to support corner cases with the unblocker
                    // assembly not being available from the assembly search path!
                    
                    try {
                        var setupType = typeof(ProxyDomainSetup);
                        var setup = (ProxyDomainSetup) proxyDomain.CreateInstanceFromAndUnwrap(
                            setupType.Assembly.Location, setupType.FullName);
                        setup.Setup();
                    } catch (Exception) {
                        DecrementProxyRef(true);
                        throw;
                    }
                }

                try {
                    var proxy = (WorkerServerClientSideProxy) proxyDomain.CreateInstanceFromAndUnwrap(
                        t.Assembly.Location, t.FullName);
                    proxy.Connect(ipcguid);
                    return proxy;
                } catch (Exception) {
                    DecrementProxyRef(true);
                    throw;
                }
            }
            
        }

        private readonly ClientSponsor proxySponsor = new ClientSponsor();
        private IWorkerServer remoteProxy;

        private event EventHandler<TaskCanceledEventArgs> taskCanceledEvent;
        public event EventHandler<TaskCanceledEventArgs> TaskCanceledEvent {
            add { this.taskCanceledEvent += this.registerRemoteHandler(value); }
            remove { this.taskCanceledEvent -= this.unregisterRemoteHandler(value); }
        }

        private event EventHandler<TaskSucceededEventArgs> taskSucceededEvent;
        public event EventHandler<TaskSucceededEventArgs> TaskSucceededEvent {
            add { this.taskSucceededEvent += this.registerRemoteHandler(value); }
            remove { this.taskSucceededEvent -= this.unregisterRemoteHandler(value); }
        }

        private event EventHandler<TaskFailedEventArgs> taskFailedEvent;
        public event EventHandler<TaskFailedEventArgs> TaskFailedEvent {
            add { this.taskFailedEvent += this.registerRemoteHandler(value); }
            remove { this.taskFailedEvent -= this.unregisterRemoteHandler(value); }
        }
        
        private event EventHandler serverDyingEvent;
        public event EventHandler ServerDyingEvent {
            add { this.serverDyingEvent += this.registerRemoteHandler(value); }
            remove { this.serverDyingEvent -= this.unregisterRemoteHandler(value); }
        }
        
        private event EventHandler serverReadyEvent;
        public event EventHandler ServerReadyEvent {
            add { this.serverReadyEvent += this.registerRemoteHandler(value); }
            remove { this.serverReadyEvent -= this.unregisterRemoteHandler(value); }
        }
        
        public void Cancel(TimeSpan cancelTimeout, ForcedCancellationMode forcedCancellationMode) {
            this.remoteProxy.Cancel(cancelTimeout, forcedCancellationMode);
        }

        public void InvokeAsync(InvocationRequest.PortableInvocationRequest invocationRequest, SecurityZone securityZone) {
            this.remoteProxy.InvokeAsync(invocationRequest, securityZone);
        }

        // must be public to be bindable to remote events
        public void OnTaskCanceled(object sender, TaskCanceledEventArgs args) {
            this.taskCanceledEvent.InvokeEvent(e => e( sender, args));
        }
        
        // must be public to be bindable to remote events
        public void OnTaskSucceeded(object sender, TaskSucceededEventArgs args) {
            this.taskSucceededEvent.InvokeEvent(e => e( sender, args));
        }
        
        // must be public to be bindable to remote events
        public void OnTaskFailed(object sender, TaskFailedEventArgs args) {
            this.taskFailedEvent.InvokeEvent(e => e( sender, args));
        }
        
        // must be public to be bindable to remote events
        public void OnServerDying(object sender, EventArgs args) {
            this.serverDyingEvent.InvokeEvent(e => e( sender, args));
        }
        
        // must be public to be bindable to remote events
        public void OnServerReady(object sender, EventArgs args) {
            this.serverReadyEvent.InvokeEvent(e => e( sender, args));
        }
        
        private void Connect(Guid ipcguid) {
            if (this.remoteProxy != null) {
                throw new InvalidOperationException("Already connected.");
            }
            
            var server = (WorkerServer)RemotingServices.Connect(typeof(WorkerServer),
                string.Format(CultureInfo.InvariantCulture,
                    @"ipc://{0}/{1}", ipcguid, typeof(WorkerServer).FullName)
            );
            this.proxySponsor.Register(server);
            this.remoteProxy = server;
            
            this.remoteProxy.ServerDyingEvent += this.OnServerDying;
            this.remoteProxy.ServerReadyEvent += this.OnServerReady;
            this.remoteProxy.TaskFailedEvent += this.OnTaskFailed;
            this.remoteProxy.TaskCanceledEvent += this.OnTaskCanceled;
            this.remoteProxy.TaskSucceededEvent += this.OnTaskSucceeded;
        }

        private T registerRemoteHandler<T>(T handler) {
            var handlerDelegate = handler as Delegate;
            if (handlerDelegate == null) {
                return handler;
            }
            
            var targetRefObject = handlerDelegate.Target as MarshalByRefObject;
            if (targetRefObject != null) {
                this.proxySponsor.Register(targetRefObject);
            }

            return handler;
        }

        private T unregisterRemoteHandler<T>(T handler) {
            var handlerDelegate = handler as Delegate;
            if (handlerDelegate == null) {
                return handler;
            }
            
            var targetRefObject = handlerDelegate.Target as MarshalByRefObject;
            if (targetRefObject != null) {
                this.proxySponsor.Unregister(targetRefObject);
            }

            return handler;
        }
        
        // Proxy Domain loads current assembly in load from context.
        // This handler resolves it using the current context.
        private static Assembly ResolveCurrentAssemblyAcrossLoadContext(object sender, ResolveEventArgs e) {
            if (e.Name == typeof(WorkerServerClientSideProxy).Assembly.FullName) {
                return typeof(WorkerServerClientSideProxy).Assembly;
            }

            return null;
        }
        
        #region Dispose & Cleanup

        public void Dispose() {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }
        
        
        private /*protected virtual*/ void Dispose(bool disposing) {
            if (disposing) {
                if (this.remoteProxy != null) {
                    this.remoteProxy.ServerDyingEvent -= this.OnServerDying;
                    this.remoteProxy.ServerReadyEvent -= this.OnServerReady;
                    this.remoteProxy.TaskFailedEvent -= this.OnTaskFailed;
                    this.remoteProxy.TaskCanceledEvent -= this.OnTaskCanceled;
                    this.remoteProxy.TaskSucceededEvent -= this.OnTaskSucceeded;
                    
                    this.remoteProxy.Dispose();
                    this.remoteProxy = null;
                    
                    this.proxySponsor.Close();
                }
            }
            
            DecrementProxyRef(disposing);
        }

        private static void DecrementProxyRef(bool mayThrow) {
            lock (proxyDomainLock) {
                AppDomain.CurrentDomain.AssemblyResolve -= ResolveCurrentAssemblyAcrossLoadContext;
                
                proxyDomainRefCount--;
                if (proxyDomainRefCount == 0 && proxyDomain != null) {
                    try {
                        AppDomain.Unload(proxyDomain);
                    } catch (CannotUnloadAppDomainException) {
                        if (mayThrow) {
                            throw;
                        }
                    }

                    proxyDomain = null;
                }
            }
        }

        ~WorkerServerClientSideProxy() {
            this.Dispose(false);   
        }

        #endregion
        
    }
}


using System;
using System.CodeDom.Compiler;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Configuration.Install;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Ipc;
using System.Text;
using System.Threading;

using Microsoft.CSharp;

namespace EpiSource.Unblocker.Hosting {
    /// <summary>This is the entry point of the host process.
    /// To execute a class library the InstallUtil.exe application included with every .net framework installation
    /// is abused.</summary>
    #if useInstallUtil
    [RunInstaller(true)]
    public sealed class WorkerServerHost : Installer {
    
        public override void Install(IDictionary stateSaver) {
            Start(this.Context.Parameters);
        }
    #else
    public sealed class WorkerServerHost {
    #endif
        public static void Start(IEnumerable<string> args) {
            var argsDict = new StringDictionary();
            
            foreach (var arg in args) {
                var parts = arg.Split('=');
                argsDict[parts[0].Substring(1)] = parts.Length == 2 ? parts[1] : "";
            }
            
            Start(argsDict);
        }
        
        private static void Start(StringDictionary args) {
            if (!args.ContainsKey("debug")) {
                throw new ArgumentException("Missing argument `debug`.");
            }
            if (!args.ContainsKey("ipcguid")) {
                throw new ArgumentException("Missing argument `ipcguid`.");
            }
            if (!args.ContainsKey("parentpid")) {
                throw new ArgumentException("Missing argument `parentpid`.");
            }
            
            DebugMode debugMode;
            if (!DebugMode.TryParse(args["debug"], out debugMode)) {
                throw new ArgumentException("Invalid value of `debug`: " + args["debug"]);
            }

            int parentPid;
            if (!int.TryParse(args["parentpid"], out parentPid)) {
                throw new ArgumentException("Invalid value of `parentpid`: " + args["parentpid"]);
            }
            
            Start(debugMode, args["ipcguid"], parentPid);
        }

        private static void Start(DebugMode debugMode, string ipcGuidString, int parentPid) {
            // serialization framework tries to find assembly on disk
            AppDomain.CurrentDomain.AssemblyResolve += (sender, args) 
                => args.Name == typeof(WorkerServerHost).Assembly.FullName ? typeof(WorkerServerHost).Assembly : null;
            
            if (debugMode == DebugMode.Debugger) {
                while (!Debugger.IsAttached) {
                    Debugger.Launch();
                    Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
                        "[server:{0}] Waiting for debugger", Process.GetCurrentProcess().Id));
                    Thread.Sleep(1000);
                }
            }
            
            IDictionary ipcProperties = new Hashtable();
            ipcProperties["name"] = "UnblockerServerChannel";
            ipcProperties["portName"] = ipcGuidString;
            ipcProperties["typeFilterLevel"] = "Full";
            var ipcChannel = new IpcChannel(ipcProperties,
                new BinaryClientFormatterSinkProvider(ipcProperties, null),
                new BinaryServerFormatterSinkProvider(ipcProperties, null));
            
            ChannelServices.RegisterChannel(ipcChannel, false);
                        
            // Create and expose server
            var server = new WorkerServer();
            RemotingServices.Marshal(server, server.GetType().FullName);
            
            // permit client to wait for this process to be ready
            var waitForProcessReadyHandle = WorkerProcess.CreateWaitForProcessReadyHandle(ipcGuidString);
            waitForProcessReadyHandle.Set();
            waitForProcessReadyHandle.Close();

            try {
                Process.GetProcessById(parentPid).WaitForExit();
            } catch {
                // exit server process anyway
            }
            
            Environment.Exit(0);
        }
        
        internal static string CreateBootstrapAssembly() {
            var knownAssembliesBuilder = new StringBuilder();
            var knownAssembliesList = AppDomain.CurrentDomain.GetAssemblies()
                                               .Where(a => !a.IsDynamic && File.Exists(a.Location))
                                               .GroupBy(a => a.FullName)
                                               .Select(g => g.First())
                                               .ToList();
            foreach (var a in knownAssembliesList) {
                knownAssembliesBuilder.AppendLine(String.Format(CultureInfo.InvariantCulture,
                    "knownAssemblies[\"{0}\"]=@\"{1}\";", a.FullName, a.Location));
            }

            var hostAssemblyLocation = typeof(WorkerServerHost).Assembly.Location;
            var hostClassName = typeof(WorkerServerHost).FullName;

            Expression<Action<string[]>> startMethod = args => WorkerServerHost.Start(args);
            var hostStartName = (startMethod.Body as MethodCallExpression).Method.Name;

            var source = @"
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Reflection;
namespace episource.unblocker.hosting {
    public static class Bootstrapper {
        
        public static void Main(string[] args) {
            IDictionary<string, string> knownAssemblies = new Dictionary<string, string>();
            " + knownAssembliesBuilder + @"
            AppDomain.CurrentDomain.AssemblyResolve += (s, e) => {
                if (knownAssemblies.ContainsKey(e.Name)) {
                    return Assembly.LoadFile(knownAssemblies[e.Name]);
                }
                return null;
            };
            Assembly hostAssembly = Assembly.LoadFile(@""" + hostAssemblyLocation + @""");
            Type hostType = hostAssembly.GetType(""" + hostClassName + @""");
            MethodInfo startMethod = hostType.GetMethod(""" + hostStartName + @""", new[] {typeof(IEnumerable<string>)});
            startMethod.Invoke(null, new [] { args });
        }
        
    }
}
             ";
            
            var provider = new CSharpCodeProvider();
            var opts = new CompilerParameters {
                GenerateInMemory = false,
                GenerateExecutable = true,
                MainClass = "episource.unblocker.hosting.Bootstrapper",
                ReferencedAssemblies = { "System.dll" }
            };

            var result = provider.CompileAssemblyFromSource(opts, source);
            if (result.NativeCompilerReturnValue != 0) {
                var ex = new InvalidOperationException("Failed to generate bootstrap assembly.");
                ex.Data["Errors"] = result.Errors;
                ex.Data["Output"] = result.Output;
                throw ex;
            }

            return result.PathToAssembly;
        }
    }
}