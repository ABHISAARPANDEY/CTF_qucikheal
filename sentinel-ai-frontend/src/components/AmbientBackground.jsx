import { motion } from 'framer-motion';






export default function AmbientBackground() {
  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 z-0 overflow-hidden">
      {}
      <motion.div
        initial={{ opacity: 0.4 }}
        animate={{ opacity: [0.35, 0.55, 0.35] }}
        transition={{ duration: 9, repeat: Infinity, ease: 'easeInOut' }}
        className="absolute -top-32 -left-32 h-[420px] w-[420px] rounded-full blur-3xl"
        style={{ background: 'radial-gradient(circle, rgba(0,212,255,0.10), transparent 60%)' }} />
      
      <motion.div
        initial={{ opacity: 0.3 }}
        animate={{ opacity: [0.25, 0.5, 0.25] }}
        transition={{ duration: 11, repeat: Infinity, ease: 'easeInOut', delay: 1.4 }}
        className="absolute bottom-[-12rem] right-[-8rem] h-[500px] w-[500px] rounded-full blur-3xl"
        style={{ background: 'radial-gradient(circle, rgba(0,255,159,0.08), transparent 60%)' }} />
      

      {}
      <motion.div
        initial={{ y: '-10vh' }}
        animate={{ y: '110vh' }}
        transition={{ duration: 9, repeat: Infinity, ease: 'linear' }}
        className="absolute left-0 right-0 h-[120px] opacity-[0.06]"
        style={{
          background:
          'linear-gradient(to bottom, transparent 0%, rgba(0,212,255,0.45) 50%, transparent 100%)'
        }} />
      

      {}
      <div
        className="absolute inset-0 opacity-[0.04]"
        style={{
          backgroundImage:
          'repeating-linear-gradient(to bottom, rgba(255,255,255,0.5) 0 1px, transparent 1px 3px)',
          mixBlendMode: 'overlay'
        }} />
      
    </div>);

}