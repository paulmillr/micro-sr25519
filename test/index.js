import { should } from 'micro-should';
import './basic.test.js';

should.runWhen(import.meta.url);