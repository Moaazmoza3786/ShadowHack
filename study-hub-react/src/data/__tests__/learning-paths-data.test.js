import { describe, it, expect } from 'vitest';
import { learningPaths } from '../learning-paths-data';

describe('programming-for-pen-testers track entry', () => {
  const track = learningPaths.find(p => p.id === 'programming-for-pen-testers');

  it('exists in learningPaths', () => {
    expect(track).toBeDefined();
  });

  it('has level === "beginner"', () => {
    expect(track.level).toBe('beginner');
  });

  it('has title === "Programming for Penetration Testers"', () => {
    expect(track.title).toBe('Programming for Penetration Testers');
  });

  it('has a non-empty titleAr string', () => {
    expect(typeof track.titleAr).toBe('string');
    expect(track.titleAr.length).toBeGreaterThan(0);
  });

  it('has a non-empty description string', () => {
    expect(typeof track.description).toBe('string');
    expect(track.description.length).toBeGreaterThan(0);
  });

  it('has a non-empty descriptionAr string', () => {
    expect(typeof track.descriptionAr).toBe('string');
    expect(track.descriptionAr.length).toBeGreaterThan(0);
  });

  it('has skills containing Python, Bash, Scripting, Tool Development', () => {
    expect(track.skills).toEqual(['Python', 'Bash', 'Scripting', 'Tool Development']);
  });

  it('has certGoals containing eJPT and OSCP', () => {
    expect(track.certGoals).toContain('eJPT');
    expect(track.certGoals).toContain('OSCP');
  });

  it('has contentModules.length === 0', () => {
    expect(track.contentModules).toHaveLength(0);
  });

  it('has youtubePlaylists.length === 0', () => {
    expect(track.youtubePlaylists).toHaveLength(0);
  });

  it('isLocked is falsy', () => {
    expect(track.isLocked).toBeFalsy();
  });

  it('has duration === "30 Hours"', () => {
    expect(track.duration).toBe('30 Hours');
  });

  it('has modules === 0', () => {
    expect(track.modules).toBe(0);
  });

  it('has icon defined (not null/undefined)', () => {
    expect(track.icon).toBeDefined();
    expect(track.icon).not.toBeNull();
  });
});
