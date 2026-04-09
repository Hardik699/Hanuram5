interface LoadingSpinnerProps {
  message?: string;
  fullScreen?: boolean;
  size?: "sm" | "md" | "lg";
}

export function LoadingSpinner({
  message = "Loading...",
  fullScreen = false,
  size = "md",
}: LoadingSpinnerProps) {
  // When fullScreen is true, show as a centered modal with dark overlay
  if (fullScreen) {
    return (
      <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
        <style>{`
          @keyframes spin-smooth {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }

          @keyframes pulse-glow {
            0%, 100% {
              box-shadow: 0 0 20px rgba(37, 99, 235, 0.5),
                          inset 0 0 20px rgba(37, 99, 235, 0.2);
              transform: scale(1);
            }
            50% {
              box-shadow: 0 0 40px rgba(37, 99, 235, 0.8),
                          inset 0 0 30px rgba(37, 99, 235, 0.3),
                          0 0 60px rgba(59, 130, 246, 0.4);
              transform: scale(1.05);
            }
          }

          @keyframes orbit {
            0% { transform: rotate(0deg) translateX(45px) rotate(0deg); }
            100% { transform: rotate(360deg) translateX(45px) rotate(-360deg); }
          }

          @keyframes float-up {
            0% {
              opacity: 0;
              transform: translateY(20px);
            }
            50% {
              opacity: 1;
            }
            100% {
              opacity: 0;
              transform: translateY(-40px);
            }
          }

          @keyframes dot-bounce {
            0%, 80%, 100% { opacity: 0.4; transform: scale(1); }
            40% { opacity: 1; transform: scale(1.2); }
          }

          .spinner-core {
            animation: pulse-glow 2.5s ease-in-out infinite;
          }

          .spinner-ring {
            animation: spin-smooth 2s linear infinite;
          }

          .orbit-dot {
            animation: orbit 3s linear infinite;
          }

          .dot-1 { animation-delay: 0s; }
          .dot-2 { animation-delay: -1s; }
          .dot-3 { animation-delay: -2s; }

          .float-particle {
            animation: float-up 2s ease-in infinite;
          }

          .particle-1 { animation-delay: 0s; }
          .particle-2 { animation-delay: 0.4s; }
          .particle-3 { animation-delay: 0.8s; }
          .particle-4 { animation-delay: 1.2s; }

          .bounce-dot {
            animation: dot-bounce 1.4s infinite;
          }
        `}</style>

        {/* Modal Card */}
        <div className="bg-white dark:bg-slate-800 rounded-3xl shadow-2xl p-12 max-w-sm mx-4 border border-blue-100 dark:border-blue-900/30">
          <div className="text-center">
            {/* Premium Loading Animation */}
            <div className="relative w-40 h-40 mx-auto mb-8">
              {/* Outer Glow Ring */}
              <div className="absolute inset-0 rounded-full bg-gradient-to-r from-blue-400/10 to-blue-500/10 blur-xl"></div>

              {/* Main Spinner Core */}
              <div className="absolute inset-2 flex items-center justify-center">
                <div className="spinner-core w-28 h-28 rounded-full bg-gradient-to-br from-blue-400 via-blue-500 to-blue-600 shadow-lg"></div>
              </div>

              {/* Rotating Ring */}
              <div className="spinner-ring absolute inset-0 rounded-full border-4 border-transparent border-t-blue-500 border-r-blue-400"></div>

              {/* Orbiting Dots */}
              <div className="absolute inset-0">
                <div className="orbit-dot dot-1 absolute w-2 h-2 bg-blue-500 rounded-full" style={{ top: '10%', left: '50%' }}></div>
                <div className="orbit-dot dot-2 absolute w-2 h-2 bg-blue-400 rounded-full" style={{ top: '50%', right: '10%' }}></div>
                <div className="orbit-dot dot-3 absolute w-2 h-2 bg-blue-600 rounded-full" style={{ bottom: '10%', left: '50%' }}></div>
              </div>

              {/* Floating Particles */}
              <div className="float-particle particle-1 absolute top-4 left-6 w-2 h-2 bg-blue-400 rounded-full blur-sm"></div>
              <div className="float-particle particle-2 absolute top-8 right-8 w-1.5 h-1.5 bg-blue-500 rounded-full blur-sm"></div>
              <div className="float-particle particle-3 absolute bottom-8 left-10 w-1.5 h-1.5 bg-blue-300 rounded-full blur-sm"></div>
              <div className="float-particle particle-4 absolute bottom-4 right-6 w-2 h-2 bg-blue-600 rounded-full blur-sm"></div>
            </div>

            {/* Message */}
            <div className="space-y-4">
              <p className="text-blue-700 dark:text-blue-300 font-bold text-lg">
                {message}
              </p>

              {/* Bouncing Dots */}
              <div className="flex justify-center items-center gap-3 h-8">
                <div className="bounce-dot w-2.5 h-2.5 rounded-full bg-blue-500"></div>
                <div className="bounce-dot w-2.5 h-2.5 rounded-full bg-blue-500" style={{ animationDelay: '0.2s' }}></div>
                <div className="bounce-dot w-2.5 h-2.5 rounded-full bg-blue-500" style={{ animationDelay: '0.4s' }}></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // When fullScreen is false, show inline
  return (
    <div className="flex items-center justify-center py-8 sm:py-12">
      <style>{`
        @keyframes spin-smooth {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }

        @keyframes pulse-glow {
          0%, 100% {
            box-shadow: 0 0 20px rgba(37, 99, 235, 0.5),
                        inset 0 0 20px rgba(37, 99, 235, 0.2);
            transform: scale(1);
          }
          50% {
            box-shadow: 0 0 40px rgba(37, 99, 235, 0.8),
                        inset 0 0 30px rgba(37, 99, 235, 0.3),
                        0 0 60px rgba(59, 130, 246, 0.4);
            transform: scale(1.05);
          }
        }

        @keyframes orbit {
          0% { transform: rotate(0deg) translateX(45px) rotate(0deg); }
          100% { transform: rotate(360deg) translateX(45px) rotate(-360deg); }
        }

        @keyframes float-up {
          0% {
            opacity: 0;
            transform: translateY(20px);
          }
          50% {
            opacity: 1;
          }
          100% {
            opacity: 0;
            transform: translateY(-40px);
          }
        }

        @keyframes dot-bounce {
          0%, 80%, 100% { opacity: 0.4; transform: scale(1); }
          40% { opacity: 1; transform: scale(1.2); }
        }

        .spinner-core {
          animation: pulse-glow 2.5s ease-in-out infinite;
        }

        .spinner-ring {
          animation: spin-smooth 2s linear infinite;
        }

        .orbit-dot {
          animation: orbit 3s linear infinite;
        }

        .dot-1 { animation-delay: 0s; }
        .dot-2 { animation-delay: -1s; }
        .dot-3 { animation-delay: -2s; }

        .float-particle {
          animation: float-up 2s ease-in infinite;
        }

        .particle-1 { animation-delay: 0s; }
        .particle-2 { animation-delay: 0.4s; }
        .particle-3 { animation-delay: 0.8s; }
        .particle-4 { animation-delay: 1.2s; }

        .bounce-dot {
          animation: dot-bounce 1.4s infinite;
        }
      `}</style>

      <div className="text-center">
        {/* Premium Loading Animation */}
        <div className="relative w-32 h-32 mx-auto mb-6">
          {/* Outer Glow Ring */}
          <div className="absolute inset-0 rounded-full bg-gradient-to-r from-blue-400/10 to-blue-500/10 blur-xl"></div>

          {/* Main Spinner Core */}
          <div className="absolute inset-2 flex items-center justify-center">
            <div className="spinner-core w-20 h-20 rounded-full bg-gradient-to-br from-blue-400 via-blue-500 to-blue-600 shadow-lg"></div>
          </div>

          {/* Rotating Ring */}
          <div className="spinner-ring absolute inset-0 rounded-full border-4 border-transparent border-t-blue-500 border-r-blue-400"></div>

          {/* Orbiting Dots */}
          <div className="absolute inset-0">
            <div className="orbit-dot dot-1 absolute w-1.5 h-1.5 bg-blue-500 rounded-full" style={{ top: '10%', left: '50%' }}></div>
            <div className="orbit-dot dot-2 absolute w-1.5 h-1.5 bg-blue-400 rounded-full" style={{ top: '50%', right: '10%' }}></div>
            <div className="orbit-dot dot-3 absolute w-1.5 h-1.5 bg-blue-600 rounded-full" style={{ bottom: '10%', left: '50%' }}></div>
          </div>

          {/* Floating Particles */}
          <div className="float-particle particle-1 absolute top-2 left-4 w-1.5 h-1.5 bg-blue-400 rounded-full blur-sm"></div>
          <div className="float-particle particle-2 absolute top-6 right-6 w-1 h-1 bg-blue-500 rounded-full blur-sm"></div>
          <div className="float-particle particle-3 absolute bottom-6 left-8 w-1 h-1 bg-blue-300 rounded-full blur-sm"></div>
          <div className="float-particle particle-4 absolute bottom-2 right-4 w-1.5 h-1.5 bg-blue-600 rounded-full blur-sm"></div>
        </div>

        {/* Message */}
        <div className="space-y-3">
          <p className="text-blue-700 dark:text-blue-300 font-semibold text-sm">
            {message}
          </p>

          {/* Bouncing Dots */}
          <div className="flex justify-center items-center gap-2 h-6">
            <div className="bounce-dot w-2 h-2 rounded-full bg-blue-500"></div>
            <div className="bounce-dot w-2 h-2 rounded-full bg-blue-500" style={{ animationDelay: '0.2s' }}></div>
            <div className="bounce-dot w-2 h-2 rounded-full bg-blue-500" style={{ animationDelay: '0.4s' }}></div>
          </div>
        </div>
      </div>
    </div>
  );
}

