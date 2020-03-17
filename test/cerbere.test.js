var CerbereStrategy = require('../lib/strategy')
  , chai = require('chai');


describe('CerbereStrategy', function() {
  
  describe('constructed', function() {
    
    describe('with normal options', function() {
      var strategy = new CerbereStrategy({
          casURL: 'https://www.example.com/cas/public',
          serviceURL: 'https://www.example.com/'
        }, function() {});
    
      it('should be named cerbere', function() {
        expect(strategy.name).to.equal('cerbere');
      });
    }); // with normal options
    
    describe('without a verify callback', function() {
      it('should throw', function() {
        expect(function() {
          new CerbereStrategy({
            casURL: 'https://www.example.com/cas/public',
            serviceURL: 'https://www.example.com/'
          });
        }).to.throw(TypeError, 'CerbereStrategy requires a verify callback');
      });
    }); // without a verify callback
    
    describe('without a casURL option', function() {
      it('should throw', function() {
        expect(function() {
          new CerbereStrategy({
            serviceURL: 'https://www.example.com/'
          }, function() {});
        }).to.throw(TypeError, 'CerbereStrategy requires a casURL option');
      });
    }); // without an casURL option
    
    describe('without a serviceURL option', function() {
      it('should throw', function() {
        expect(function() {
          new CerbereStrategy({
            casURL: 'https://www.example.com/cas/public'
          }, function() {});
        }).to.throw(TypeError, 'CerbereStrategy requires a serviceURL option');
      });
    }); // without a serviceURL option
    
    describe('with only a verify callback', function() {
      it('should throw', function() {
        expect(function() {
          new CerbereStrategy(function() {});
        }).to.throw(TypeError, 'CerbereStrategy requires a casURL option');
      });
    }); // with only a verify callback
    
  }); // constructed
});