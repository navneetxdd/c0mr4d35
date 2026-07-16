"use client";

import { useEffect, useRef } from "react";

const vertexShaderSource = `
  attribute vec2 position;
  void main() {
    gl_Position = vec4(position, 0.0, 1.0);
  }
`;

const fragmentShaderSource = `
  precision mediump float;

  uniform vec2 u_resolution;
  uniform float u_time;
  uniform vec2 u_mouse;

  float hash(vec2 p) {
    return fract(sin(dot(p, vec2(12.9898, 78.233))) * 43758.5453123);
  }

  vec3 getLiveColor() {
    return vec3(184.0 / 255.0, 240.0 / 255.0, 76.0 / 255.0);
  }

  void main() {
    vec2 uv = gl_FragCoord.xy / u_resolution.xy;
    vec2 p = uv * 2.0 - 1.0;
    p.x *= u_resolution.x / u_resolution.y;

    vec2 mouse = u_mouse / u_resolution.xy;
    mouse = mouse * 2.0 - 1.0;
    mouse.x *= u_resolution.x / u_resolution.y;

    vec2 gridUV = uv * 20.0;
    gridUV.y += sin(gridUV.x * 0.5 + u_time * 0.5) * 0.1;
    float grid1 = max(step(0.98, fract(gridUV.x)), step(0.98, fract(gridUV.y)));
    float grid2 = max(step(0.95, fract(uv * 80.0)), step(0.95, fract((uv * 80.0).yx)));
    float gridAlpha = (grid1 * 0.3) + (grid2 * 0.06);

    float scanAlpha = sin(uv.y * 400.0 + u_time * 8.0) * 0.03;
    float pulse = smoothstep(0.98, 1.0, sin(uv.y * 5.0 - u_time * 1.5));

    float distToMouse = length(p - mouse);
    float glow = (1.0 - smoothstep(0.0, 1.2, distToMouse)) * (0.85 + 0.15 * sin(u_time * 3.0));
    float vignette = 1.0 - smoothstep(0.5, 1.6, length(p));

    vec3 baseColor = getLiveColor();
    vec3 color = baseColor * (gridAlpha + pulse * 0.35);
    color += baseColor * glow * 0.12;
    color *= vignette;
    color -= scanAlpha;
    color += hash(uv + u_time) * 0.05;
    color *= 0.4;

    gl_FragColor = vec4(color, 1.0);
  }
`;

function createShader(gl: WebGLRenderingContext, type: number, source: string) {
  const shader = gl.createShader(type);
  if (!shader) return null;
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    gl.deleteShader(shader);
    return null;
  }
  return shader;
}

/** Login-only WebGL backdrop. Caps DPR, pauses when hidden / reduced-motion. */
export function SystemOverrideShader() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      return;
    }

    const gl = canvas.getContext("webgl", {
      alpha: false,
      antialias: false,
      powerPreference: "low-power",
    });
    if (!gl) return;

    const vertexShader = createShader(gl, gl.VERTEX_SHADER, vertexShaderSource);
    const fragmentShader = createShader(gl, gl.FRAGMENT_SHADER, fragmentShaderSource);
    if (!vertexShader || !fragmentShader) return;

    const program = gl.createProgram();
    if (!program) return;
    gl.attachShader(program, vertexShader);
    gl.attachShader(program, fragmentShader);
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) return;
    gl.useProgram(program);

    const positionBuffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]),
      gl.STATIC_DRAW,
    );

    const positionLocation = gl.getAttribLocation(program, "position");
    gl.enableVertexAttribArray(positionLocation);
    gl.vertexAttribPointer(positionLocation, 2, gl.FLOAT, false, 0, 0);

    const resolutionLocation = gl.getUniformLocation(program, "u_resolution");
    const timeLocation = gl.getUniformLocation(program, "u_time");
    const mouseLocation = gl.getUniformLocation(program, "u_mouse");

    let animationFrameId = 0;
    let mouseX = window.innerWidth / 2;
    let mouseY = window.innerHeight / 2;
    let targetMouseX = mouseX;
    let targetMouseY = mouseY;
    let running = true;
    let lastFrame = 0;
    const TARGET_MS = 1000 / 30;

    const handleMouseMove = (e: MouseEvent) => {
      targetMouseX = e.clientX;
      targetMouseY = window.innerHeight - e.clientY;
    };

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 1);
      const w = window.innerWidth;
      const h = window.innerHeight;
      canvas.width = Math.max(1, Math.floor(w * dpr));
      canvas.height = Math.max(1, Math.floor(h * dpr));
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
      gl.viewport(0, 0, canvas.width, canvas.height);
    };

    const onVisibility = () => {
      running = document.visibilityState === "visible";
      if (running) {
        lastFrame = 0;
        animationFrameId = requestAnimationFrame(render);
      }
    };

    window.addEventListener("mousemove", handleMouseMove, { passive: true });
    window.addEventListener("resize", resize, { passive: true });
    document.addEventListener("visibilitychange", onVisibility);
    resize();

    const startTime = performance.now();

    const render = (time: number) => {
      if (!running) return;
      if (time - lastFrame < TARGET_MS) {
        animationFrameId = requestAnimationFrame(render);
        return;
      }
      lastFrame = time;

      mouseX += (targetMouseX - mouseX) * 0.1;
      mouseY += (targetMouseY - mouseY) * 0.1;

      gl.uniform2f(resolutionLocation, canvas.width, canvas.height);
      gl.uniform1f(timeLocation, (time - startTime) * 0.001);
      gl.uniform2f(mouseLocation, mouseX * (canvas.width / window.innerWidth), mouseY * (canvas.height / window.innerHeight));
      gl.drawArrays(gl.TRIANGLES, 0, 6);
      animationFrameId = requestAnimationFrame(render);
    };

    animationFrameId = requestAnimationFrame(render);

    return () => {
      running = false;
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("resize", resize);
      window.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="pointer-events-none fixed inset-0 z-0 h-full w-full opacity-50 mix-blend-screen"
      aria-hidden
    />
  );
}
