import { motion } from 'framer-motion';
import { useThreatReaction } from '../lib/useThreatReaction';



























export function ThreatReactionOverlay() {
  const { severity, intensity, isPulsing, flashKey, flashTone } = useThreatReaction();




  const flashAlpha =
  severity === 'critical' ? 0.10 :
  severity === 'high' ? 0.09 :
  severity === 'medium' ? 0.06 :
  0;


  const vignetteAlpha = intensity * 0.16;

  return (
    <div className="pointer-events-none fixed inset-0 z-[60]">
      {

      }
      {flashKey >= 0 && flashTone && flashAlpha > 0 &&
      <motion.div
        key={flashKey}
        aria-hidden
        initial={{ opacity: 0 }}
        animate={{ opacity: [0, flashAlpha, 0] }}
        transition={{ duration: 0.55, ease: 'easeOut', times: [0, 0.25, 1] }}
        className="absolute inset-0"
        style={{
          backgroundColor: flashTone,
          mixBlendMode: 'screen'
        }} />

      }

      {


      }
      {isPulsing && flashTone &&
      <motion.div
        aria-hidden
        initial={{ opacity: 0 }}
        animate={{ opacity: [vignetteAlpha * 0.7, vignetteAlpha, vignetteAlpha * 0.7] }}
        exit={{ opacity: 0 }}
        transition={{ duration: 2.6, repeat: Infinity, ease: 'easeInOut' }}
        className="absolute inset-0"
        style={{
          boxShadow: `inset 0 0 140px 30px ${flashTone}`
        }} />

      }
    </div>);

}