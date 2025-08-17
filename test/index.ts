import { should } from 'micro-should';
import './basic.test.ts';

should.runWhen(import.meta.url);
